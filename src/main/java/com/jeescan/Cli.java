package com.jeescan;

import com.jeescan.core.Detector;
import com.jeescan.core.Engine;
import com.jeescan.core.Http;
import com.jeescan.core.Registry;
import com.jeescan.core.Result;

import java.util.ArrayList;
import java.util.List;

/**
 * 命令行模式。
 *
 * 输出风格（简洁）：每条只打一行
 *   [+] 漏洞名          —— 存在
 *   [-] 漏洞名          —— 不存在
 *   [?] 漏洞名 原因     —— 待确认
 *   [!] 漏洞名 原因     —— 请求异常
 *
 * --echo 时才展开完整 payload 与响应明细。
 */
public final class Cli {

    public static void main(String[] args) {
        try {
            System.setOut(new java.io.PrintStream(
                    new java.io.FileOutputStream(java.io.FileDescriptor.out), true, "UTF-8"));
            System.setErr(new java.io.PrintStream(
                    new java.io.FileOutputStream(java.io.FileDescriptor.err), true, "UTF-8"));
        } catch (Exception ignored) {}

        String url = null;
        String prefix = "";
        String token = "";
        String oob = "";
        String cmd = "id";
        int sleep = 0;
        int timeout = 20;
        boolean echo = false;
        boolean sensitive = false;
        String only = null;
        String proxy = "";      // 形如 http://127.0.0.1:8080 或 socks5://127.0.0.1:1080
        String proxyAuth = "";  // user:pass

        for (int i = 1; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--prefix": prefix = next(args, ++i); break;
                case "--token": token = next(args, ++i); break;
                case "--sleep": sleep = toInt(next(args, ++i), 0); break;
                case "--timeout": timeout = toInt(next(args, ++i), 20); break;
                case "--oob": oob = next(args, ++i); break;
                case "--cmd": cmd = next(args, ++i); break;
                case "--only": only = next(args, ++i); break;
                case "--echo": echo = true; break;
                case "--sensitive": sensitive = true; break;
                case "--all": echo = true; break;
                case "--proxy": proxy = next(args, ++i); break;
                case "--proxy-auth": proxyAuth = next(args, ++i); break;
                default:
                    if (url == null && !a.startsWith("--")) url = a;
                    break;
            }
        }

        if (url == null || url.isEmpty()) {
            System.out.println("jeecgboot-tiplus 漏洞检测 by dollmarker v1.0");
            System.out.println();
            System.out.println("用法: java -jar jeecgboot-tiplus.jar --cli <url> [选项]");
            System.out.println("  --prefix <p>     二级接口，如 jeecg-boot 或 api；默认空");
            System.out.println("  --token  <t>     X-Access-Token");
            System.out.println("  --sleep  <n>     请求间隔秒（WAF 环境建议 6）");
            System.out.println("  --only   <ids>   只跑指定编号，如 1,2,20");
            System.out.println("  --echo           展开完整 payload 与响应明细");
            System.out.println("  --oob    <u>     JDBC RCE 的 XML/回连地址");
            System.out.println("  --cmd    <c>     执行命令（默认 id）");
            System.out.println("  --sensitive      启用 #24 默认口令 / #25 密码重置");
            System.out.println("  --proxy  <url>   代理，如 http://127.0.0.1:8080 或 socks5://127.0.0.1:1080");
            System.out.println("  --proxy-auth <u:p>  代理认证 user:pass");
            return;
        }

        Http http = new Http(url, token);
        http.setSleep(sleep * 1000);
        http.setTimeout(timeout * 1000);

        // 代理
        if (proxy != null && !proxy.isEmpty()) {
            String type = "HTTP";
            String hp = proxy;
            int sep = proxy.indexOf("://");
            if (sep > 0) {
                String scheme = proxy.substring(0, sep).toLowerCase();
                type = scheme.startsWith("socks") ? "SOCKS" : "HTTP";
                hp = proxy.substring(sep + 3);
            }
            int colon = hp.lastIndexOf(':');
            String ph = colon > 0 ? hp.substring(0, colon) : hp;
            int pp = colon > 0 ? toInt(hp.substring(colon + 1), 0) : 0;
            String pu = "";
            String ppass = "";
            if (proxyAuth != null && !proxyAuth.isEmpty()) {
                int c2 = proxyAuth.indexOf(':');
                pu = c2 > 0 ? proxyAuth.substring(0, c2) : proxyAuth;
                ppass = c2 > 0 ? proxyAuth.substring(c2 + 1) : "";
            }
            http.setProxy(type, ph, pp, pu, ppass);
            System.out.println("代理 : " + http.getProxyDesc());
        }

        Detector.Ctx ctx = new Detector.Ctx(http, prefix, token, echo, oob, cmd, sensitive);

        List<Detector> all = Registry.all();
        List<Detector> list = new ArrayList<>();
        if (only != null && !only.isEmpty()) {
            for (String s : only.split(",")) {
                String id = s.trim();
                for (Detector d : all) {
                    if (d.getId().equals(id)) list.add(d);
                }
            }
        } else {
            list = all;
        }

        // 未启用敏感操作时剔除 #24 #25
        if (!sensitive) {
            List<Detector> f = new ArrayList<>();
            for (Detector d : list) {
                if ("24".equals(d.getId()) || "25".equals(d.getId())) continue;
                f.add(d);
            }
            list = f;
        }

        System.out.println("jeecgboot-tiplus 漏洞检测 by dollmarker v1.0");
        System.out.println("目标 : " + url);
        System.out.println("接口 : " + (prefix.isEmpty() ? "(根)" : prefix)
                + "    检测项 : " + list.size());
        System.out.println();

        final boolean echoOut = echo;
        Engine eng = new Engine();
        List<Result> rs = eng.run(list, ctx, new Engine.Listener() {
            public void onStart(Detector d, int i, int total) {
                // 简洁模式不打开始行
            }

            public void onDone(Result r, int i, int total) {
                System.out.println(line(r));
                if (echoOut) {
                    System.out.println(r.dump());
                }
            }

            public void onLog(String l) { System.out.println(l); }
            public void onFinish(List<Result> results) {}
        });

        // 汇总：只列存在与待确认
        int vuln = 0, maybe = 0;
        List<Result> hits = new ArrayList<>();
        List<Result> unsure = new ArrayList<>();
        for (Result r : rs) {
            if (r.isVuln()) { vuln++; hits.add(r); }
            else if (r.isMaybe()) { maybe++; unsure.add(r); }
        }
        System.out.println();
        System.out.println("----------------------------------------");
        System.out.println("存在 " + vuln + "    待确认 " + maybe
                + "    共 " + rs.size() + " 项");
        if (!hits.isEmpty()) {
            System.out.println();
            for (Result r : hits) {
                System.out.println("[+] #" + r.id + " " + r.name
                        + "  (" + r.severity + ")");
            }
        }
        if (!unsure.isEmpty()) {
            System.out.println();
            for (Result r : unsure) {
                System.out.println("[?] #" + r.id + " " + r.name);
            }
        }
        if (vuln == 0 && maybe == 0) {
            System.out.println();
            System.out.println("未发现漏洞。加 --echo 可查看每条 payload 自行核对。");
        }
    }

    /** 单行结果：[-] 无漏洞 / [+] 有漏洞 / [?] 待确认 / [!] 异常。供 CLI 与 GUI 共用。 */
    public static String line(Result r) {
        String tag;
        switch (r.state) {
            case VULN:  tag = "[+]"; break;
            case MAYBE: tag = "[?]"; break;
            case ERROR: tag = "[!]"; break;
            case SKIP:  tag = "[-]"; break;
            default:    tag = "[-]"; break;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(tag).append(' ').append(r.name);
        // 只有非"不存在"才带原因，避免正常项刷太多字
        if (r.state != Result.State.SAFE && r.verdict != null && !r.verdict.isEmpty()) {
            String v = r.verdict;
            if (v.length() > 90) v = v.substring(0, 90) + "...";
            sb.append("  ").append(v);
        }
        return sb.toString();
    }

    private static String next(String[] a, int i) {
        return i < a.length ? a[i] : "";
    }

    private static int toInt(String s, int d) {
        try { return Integer.parseInt(s.trim()); } catch (Exception e) { return d; }
    }
}
