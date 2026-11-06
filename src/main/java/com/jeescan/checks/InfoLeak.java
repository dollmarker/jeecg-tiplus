package com.jeescan.checks;

import com.jeescan.core.Detector;
import com.jeescan.core.Http;
import com.jeescan.core.Json;
import com.jeescan.core.Result;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 信息泄露 / 未授权 / 目录遍历 / 密码重置 / 账号枚举（#20-#23 #25 #26）
 * 统一结构：正例必须"有数据"，反例必须"无数据"。
 */
public final class InfoLeak {

    private InfoLeak() {}

    /** 通用：GET 探针 + 反例校验。 */
    abstract static class GetProbe extends Detector {
        GetProbe(String id, String name, String endpoint, String cve,
                 String severity, boolean needsAuth, String note) {
            super(id, name, endpoint, cve, severity, needsAuth, note);
        }

        /** 正例路径（相对，会过 ctx.p） */
        abstract String posPath(Ctx ctx);

        /** 反例路径 —— 用随机值让服务端查不到 */
        abstract String negPath(Ctx ctx, String rnd);

        /** 判定正例是否"有信号" */
        abstract boolean posHit(Http.Resp r, String raw);

        /** 判定反例是否"有信号"（应返回 false） */
        boolean negHit(Http.Resp r, String raw) { return posHit(r, raw); }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;

            String pp = posPath(ctx);
            Http.Resp pos = h.get(pp);
            res.trace("A. 正例", "GET", h.url(pp), null, pos, "期望返回数据");
            if (isRst(pos)) return res.set(Result.State.ERROR, "正例被重置：" + pos.err);

            if (!posHit(pos, pos.text)) {
                return res.set(Result.State.SAFE, "正例未返回预期数据：" + pos.brief(120));
            }

            String r = rnd(8);
            String np = negPath(ctx, r);
            Http.Resp neg = h.get(np);
            res.trace("B. 反例（随机值 " + r + "）", "GET", h.url(np), null, neg,
                    "查不到的数据应无信号，否则说明是通用兜底响应");

            if (negHit(neg, neg.text)) {
                return res.set(Result.State.MAYBE,
                        "反例同样有信号 —— 疑似通用响应，判定为误报");
            }

            res.ev("正例有数据，反例（随机值）无数据，差分成立");
            res.repro("curl -s '" + h.url(pp) + "'");
            return res.set(Result.State.VULN, "未授权访问确认，正例返回敏感数据");
        }
    }

    // ---------------------------------------------------------------- #20
    public static class QuerySysUser extends GetProbe {
        public QuerySysUser() {
            super("20", "querySysUser 泄露", "/sys/user/querySysUser",
                  "未授权", "high", false,
                  "按用户名查用户信息；正例 admin 有数据 + 反例随机用户名无数据");
        }

        String posPath(Ctx ctx) { return ctx.p("sys/user/querySysUser?username=admin"); }

        String negPath(Ctx ctx, String r) {
            return ctx.p("sys/user/querySysUser?username=__n0pe" + r + "__");
        }

        boolean posHit(Http.Resp r, String raw) {
            if (!jsonSuccess(r)) return false;
            String u = Json.str(raw, "result.username");
            return u != null && !u.isEmpty();
        }
    }

    // ---------------------------------------------------------------- #21
    public static class CheckOnlyUser extends GetProbe {
        public CheckOnlyUser() {
            super("21", "checkOnlyUser 枚举", "/sys/user/checkOnlyUser",
                  "未授权", "medium", false,
                  "响应含'账号已存在'即确认；反例用随机用户名");
        }

        String posPath(Ctx ctx) { return ctx.p("sys/user/checkOnlyUser?username=admin"); }

        String negPath(Ctx ctx, String r) {
            return ctx.p("sys/user/checkOnlyUser?username=__n0pe" + r + "__");
        }

        boolean posHit(Http.Resp r, String raw) {
            return has(r, "账号已存在") || has(r, "已存在");
        }
    }

    // ---------------------------------------------------------------- #22
    public static class Httptrace extends GetProbe {
        public Httptrace() {
            super("22", "httptrace 泄露", "/actuator/httptrace",
                  "未授权", "high", false,
                  "httptrace 可能含管理员 Token；traces 非空即确认");
        }

        String posPath(Ctx ctx) { return ctx.p("actuator/httptrace"); }

        String negPath(Ctx ctx, String r) { return ctx.p("actuator/__n0pe" + r + "__"); }

        boolean posHit(Http.Resp r, String raw) {
            return raw != null && (raw.contains("\"traces\"") || raw.contains("\"timestamp\""));
        }

        boolean negHit(Http.Resp r, String raw) {
            return raw != null && raw.contains("\"traces\"");
        }
    }

    // ---------------------------------------------------------------- #23
    public static class DataSourceList extends GetProbe {
        public DataSourceList() {
            super("23", "数据源账密泄露", "/sys/dataSource/list",
                  "未授权", "critical", false,
                  "POC 来源 JeecgGo: /sys/dataSource/list（非 jmreport/datasource/list）");
        }

        String posPath(Ctx ctx) { return ctx.p("sys/dataSource/list"); }

        String negPath(Ctx ctx, String r) { return ctx.p("sys/__n0pe" + r + "__"); }

        boolean posHit(Http.Resp r, String raw) {
            if (!jsonSuccess(r)) return false;
            // 兼容 result 为数组或 {records:[]} 两种形态
            Object res = Json.get(raw, "result");
            if (res instanceof java.util.List) {
                return !((java.util.List<?>) res).isEmpty();
            }
            Object recs = Json.get(raw, "result.records");
            return recs instanceof java.util.List && !((java.util.List<?>) recs).isEmpty();
        }
    }

    // ---------------------------------------------------------------- #33
    public static class DictList extends GetProbe {
        public DictList() {
            super("33", "jmreport dict/list 未授权", "/jmreport/dict/list",
                  "未授权", "medium", false,
                  "未授权列出系统全部字典，泄漏业务模型");
        }

        String posPath(Ctx ctx) { return ctx.p("jmreport/dict/list?pageSize=200&pageNo=1"); }

        String negPath(Ctx ctx, String r) { return ctx.p("jmreport/__n0pe" + r + "__"); }

        boolean posHit(Http.Resp r, String raw) {
            if (!jsonSuccess(r)) return false;
            Object recs = Json.get(raw, "result.records");
            if (recs instanceof java.util.List && !((java.util.List<?>) recs).isEmpty()) {
                return true;
            }
            Object res = Json.get(raw, "result");
            return res instanceof java.util.List && !((java.util.List<?>) res).isEmpty();
        }
    }

    // ---------------------------------------------------------------- #25
    public static class PasswordChange extends Detector {
        public PasswordChange() {
            super("25", "passwordChange 改密",
                  "/sys/user/passwordChange", "逻辑漏洞", "critical", false,
                  "用【不存在的用户名】安全探测；接口返回'未找到对应实体'即为未鉴权可达，绝不真重置任何账号");
        }

        @Override
        public Result run(Ctx ctx) {
            Result res = newResult();
            Http h = ctx.http;

            // 安全设计：只用不可能存在的用户名探测，绝不碰 admin
            String probeUser = "__jscan_probe_" + rnd(10) + "__";
            String path = ctx.p("sys/user/passwordChange?username=" + probeUser
                    + "&password=x&smscode=&phone=");
            Http.Resp r = h.get(path);
            res.trace("A. 未鉴权可达性（不存在的用户 " + probeUser + "）", "GET",
                    h.url(path), null, r,
                    "只探测接口是否未鉴权；绝不使用真实用户名");
            if (isRst(r)) return res.set(Result.State.ERROR, "请求被重置：" + r.err);

            String msg = jsonMsg(r);
            boolean reachable = has(r, "未找到对应实体") || has(r, "不存在");

            if (!reachable) {
                // 带一个明显非法的 username 再看是否要求鉴权
                boolean needAuth = has(r, "Token失效") || has(r, "请重新登录")
                        || has(r, "AuthenticationException") || has(r, "权限");
                if (needAuth) {
                    return res.set(Result.State.SAFE, "接口需要认证，未鉴权不可达");
                }
                return res.set(Result.State.SAFE, "未能确认未鉴权可达：" + msg);
            }

            res.ev("接口未鉴权可达（用不存在用户探测，返回：" + msg + "）");
            res.ev("【未执行】任何真实账号的密码重置");
            res.repro("curl -s '" + h.url(path) + "'   # 安全探测，非真实账号");
            res.repro("# 若要确认危害，需在授权下用可控测试账号验证，本工具不自动执行");
            return res.set(Result.State.VULN,
                    "接口未鉴权且无验证码校验（已用不存在用户验证，未重置任何真实账号）");
        }
    }

    // ---------------------------------------------------------------- #26
    public static class FileTree extends GetProbe {
        public FileTree() {
            super("26", "fileTree 目录遍历", "GET /online/cgform/head/fileTree",
                  "路径遍历", "medium", false,
                  "parentPath 可控读取服务器目录");
        }

        String posPath(Ctx ctx) {
            return ctx.p("online/cgform/head/fileTree?parentPath=/&_t=" + System.currentTimeMillis());
        }

        String negPath(Ctx ctx, String r) {
            return ctx.p("online/cgform/head/fileTree?parentPath=/__n0pe" + r + "__&_t="
                    + System.currentTimeMillis());
        }

        boolean posHit(Http.Resp r, String raw) {
            if (!jsonSuccess(r)) return false;
            Object res = Json.get(raw, "result");
            return res instanceof java.util.List && !((java.util.List<?>) res).isEmpty();
        }
    }
}
