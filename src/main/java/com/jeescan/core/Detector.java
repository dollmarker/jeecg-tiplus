package com.jeescan.core;

import java.security.SecureRandom;
import java.util.Map;

/**
 * 检测器基类。
 *
 * 提供"严格自检"的三件基础设施：
 *   1) 随机标记（marker）：每次检测生成独一无二的随机串，避免命中历史缓存/其他测试残留
 *   2) 差分断言（diff）：正例必须成立 + 反例必须不成立，否则判 MAYBE 或 SAFE
 *   3) 安全上限：敏感操作（爆破、写文件）默认关闭，需显式开启
 */
public abstract class Detector {

    protected static final SecureRandom RND = new SecureRandom();

    protected final String id;
    protected final String name;
    protected final String endpoint;
    protected final String cve;
    protected final String severity;
    protected final boolean needsAuth;
    protected final String note;

    /** 是否需要 Token 才能打（UI 会提示）。 */
    public boolean requiresToken() { return needsAuth; }

    public Detector(String id, String name, String endpoint, String cve,
                    String severity, boolean needsAuth, String note) {
        this.id = id;
        this.name = name;
        this.endpoint = endpoint;
        this.cve = cve;
        this.severity = severity;
        this.needsAuth = needsAuth;
        this.note = note;
    }

    public abstract Result run(Ctx ctx);

    public String getId()       { return id; }
    public String getName()     { return name; }
    public String getEndpoint() { return endpoint; }
    public String getCve()      { return cve; }
    public String getSeverity() { return severity; }
    public String getNote()     { return note; }

    public Result newResult() {
        return new Result(id, name, endpoint, cve, severity, needsAuth, note);
    }

    // ------------------------------------------------------------ 标记

    /** 生成随机小写字母数字串。 */
    public static String rnd(int n) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) sb.append(alphabet.charAt(RND.nextInt(alphabet.length())));
        return sb.toString();
    }

    /** 生成随机数字串（长度 n）。 */
    public static String rndDigits(int n) {
        StringBuilder sb = new StringBuilder(n);
        sb.append((char) ('1' + RND.nextInt(9)));
        for (int i = 1; i < n; i++) sb.append((char) ('0' + RND.nextInt(10)));
        return sb.toString();
    }

    /**
     * 算术探针：用两个随机数算乘积，服务端若求值则必得该结果。
     * 返回 [表达式, 期望结果]，例如 ["=23*17","391"]。
     */
    public static String[] arithProbe() {
        int a = 11 + RND.nextInt(89);
        int b = 11 + RND.nextInt(89);
        return new String[]{"=" + a + "*" + b, String.valueOf(a * b)};
    }

    /**
     * 字符串拼接探针：排除"数字碰巧相等"的误判。
     * 返回 [表达式, 期望结果]。
     */
    public static String[] concatProbe() {
        String p = rnd(6);
        String q = rnd(6);
        return new String[]{"=\"" + p + "\"+\"" + q + "\"", p + q};
    }

    // ------------------------------------------------------------ 断言

    /** 响应是否被 WAF 重置 / 超时。 */
    protected static boolean isRst(Http.Resp r) {
        return r == null || r.rst;
    }

    /** 响应体是否包含某串（大小写敏感）。 */
    protected static boolean has(Http.Resp r, String s) {
        return r != null && !r.rst && r.text != null && r.text.contains(s);
    }

    /** 响应体是否包含某串（忽略大小写）。 */
    protected static boolean hasIgnoreCase(Http.Resp r, String s) {
        return r != null && !r.rst && r.text != null
                && r.text.toLowerCase().contains(s.toLowerCase());
    }

    protected static boolean jsonSuccess(Http.Resp r) {
        if (r == null || r.rst) return false;
        Map<String, Object> m = Json.parseObject(r.text);
        if (m == null) return false;
        Object ok = m.get("success");
        return Boolean.TRUE.equals(ok) || "true".equals(String.valueOf(ok));
    }

    protected static String jsonMsg(Http.Resp r) {
        if (r == null || r.rst) return "";
        Map<String, Object> m = Json.parseObject(r.text);
        if (m == null) return "";
        Object msg = m.get("message");
        return msg == null ? "" : String.valueOf(msg);
    }

    /**
     * 差分断言的核心：
     *   positive 必须"有信号"，negative 必须"无信号"。
     * 返回 true 才算确认漏洞。
     */
    protected static boolean diff(boolean positive, boolean negative) {
        return positive && !negative;
    }

    // ------------------------------------------------------------ 上下文

    /** 传给检测器的运行上下文。 */
    public static final class Ctx {
        public final Http http;
        /** 用户填的二级接口（可为空，表示直连根）；本工具不内置任何前缀。 */
        public final String prefix;
        public final String token;
        public final boolean verbose;
        /** 命令执行 / 外带类检测用的 XML 或回连地址。 */
        public final String oobUrl;
        public final String cmd;
        public final boolean enableSensitive;

        public Ctx(Http http, String prefix, String token, boolean verbose,
                   String oobUrl, String cmd, boolean enableSensitive) {
            this.http = http;
            this.prefix = prefix == null ? "" : prefix;
            this.token = token;
            this.verbose = verbose;
            this.oobUrl = oobUrl;
            this.cmd = cmd == null || cmd.isEmpty() ? "id" : cmd;
            this.enableSensitive = enableSensitive;
        }

        /**
         * 拼接完整路径。prefix 由用户填写，本工具不自动加 jeecg-boot。
         * prefix 形如 "jeecg-boot" 或 "api" 或 ""。
         */
        public String p(String path) {
            String p = path == null ? "" : path;
            if (p.startsWith("/")) p = p.substring(1);
            if (prefix == null || prefix.isEmpty()) return p;
            String pre = prefix;
            while (pre.startsWith("/")) pre = pre.substring(1);
            while (pre.endsWith("/")) pre = pre.substring(0, pre.length() - 1);
            return pre + "/" + p;
        }
    }
}
