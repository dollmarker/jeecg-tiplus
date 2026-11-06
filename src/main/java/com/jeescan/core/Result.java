package com.jeescan.core;

import java.util.ArrayList;
import java.util.List;

/**
 * 一次检测的结果。
 *
 * 设计要点：把"原始请求/响应"完整保留下来，供 UI 的"回显检测"勾选框
 * 二次查看。这样即使判定为"不存在"，用户也能自己核对 payload 是否正确，
 * 而不是只看到一句"未发现"。
 */
public final class Result {

    public enum State {
        VULN("存在", 2),
        SAFE("不存在", 0),
        MAYBE("待确认", 1),
        SKIP("已跳过", 0),
        ERROR("请求异常", 0);

        public final String label;
        public final int rank;

        State(String label, int rank) { this.label = label; this.rank = rank; }
    }

    /** 单次 HTTP 往返记录。 */
    public static final class Trace {
        public final String title;      // 例如 "正例: id=1"
        public final String method;
        public final String url;
        public final String reqBody;
        public final int status;
        public final long costMs;
        public final boolean rst;
        public final String respText;
        public final String note;       // 该请求的作用说明

        public Trace(String title, String method, String url, String reqBody,
                     Http.Resp r, String note) {
            this.title = title;
            this.method = method;
            this.url = url;
            this.reqBody = reqBody;
            this.status = r == null ? -1 : r.status;
            this.costMs = r == null ? 0 : r.costMs;
            this.rst = r == null || r.rst;
            this.respText = r == null ? "" : r.text;
            this.note = note;
        }

        public String respBrief(int n) {
            if (rst) return "[RST/超时]";
            String t = respText.replaceAll("\\s+", " ");
            return t.length() > n ? t.substring(0, n) + "..." : t;
        }
    }

    // ----------------------------------------------------------------

    public final String id;             // 唯一编号 1..26
    public final String name;           // 名称
    public final String endpoint;       // 二级接口（不含前缀）
    public final String cve;            // CVE / 技术点
    public final String severity;       // critical/high/medium/low
    public final boolean needsAuth;     // 是否需要 token
    public final String note;           // 判定依据说明

    public State state = State.SKIP;
    public String verdict = "";         // 一句话结论
    public final List<Trace> traces = new ArrayList<>();
    public final List<String> evidence = new ArrayList<>();
    public final List<String> repro = new ArrayList<>();

    public long startMs;
    public long endMs;

    public Result(String id, String name, String endpoint, String cve,
                  String severity, boolean needsAuth, String note) {
        this.id = id;
        this.name = name;
        this.endpoint = endpoint;
        this.cve = cve;
        this.severity = severity;
        this.needsAuth = needsAuth;
        this.note = note;
    }

    public boolean isVuln()  { return state == State.VULN; }
    public boolean isMaybe() { return state == State.MAYBE; }
    public long costMs()     { return endMs - startMs; }

    public Result trace(String title, String method, String url, String reqBody,
                        Http.Resp r, String note) {
        traces.add(new Trace(title, method, url, reqBody, r, note));
        return this;
    }

    public Result ev(String s) {
        evidence.add(s);
        return this;
    }

    public Result repro(String s) {
        repro.add(s);
        return this;
    }

    public Result set(State st, String verdict) {
        this.state = st;
        this.verdict = verdict == null ? "" : verdict;
        return this;
    }

    /** 完整报告文本，供"回显检测"面板使用。 */
    public String dump() {
        StringBuilder sb = new StringBuilder();
        sb.append("=").append(rep('=', 74)).append("\n");
        sb.append("[").append(id).append("] ").append(name).append("\n");
        sb.append("  端点   : ").append(endpoint).append("\n");
        if (cve != null && !cve.isEmpty()) sb.append("  CVE/技术: ").append(cve).append("\n");
        sb.append("  等级   : ").append(severity).append("   认证: ")
          .append(needsAuth ? "需 Token" : "未授权").append("\n");
        sb.append("  判定   : ").append(state.label);
        if (!verdict.isEmpty()) sb.append(" —— ").append(verdict);
        sb.append("\n");
        if (!note.isEmpty()) sb.append("  判定依据: ").append(note).append("\n");
        sb.append("  耗时   : ").append(costMs()).append(" ms\n");

        if (!evidence.isEmpty()) {
            sb.append("\n  --- 证据 ---\n");
            for (String e : evidence) sb.append("  * ").append(e).append("\n");
        }
        if (!repro.isEmpty()) {
            sb.append("\n  --- 复现命令 ---\n");
            for (String r : repro) sb.append("  $ ").append(r).append("\n");
        }
        if (!traces.isEmpty()) {
            sb.append("\n  --- 请求/响应明细 (").append(traces.size()).append(" 条) ---\n");
            for (int i = 0; i < traces.size(); i++) {
                Trace t = traces.get(i);
                sb.append("\n  [").append(i + 1).append("] ").append(t.title).append("\n");
                if (t.note != null && !t.note.isEmpty()) {
                    sb.append("      说明: ").append(t.note).append("\n");
                }
                sb.append("      ").append(t.method).append(" ").append(t.url).append("\n");
                if (t.reqBody != null && !t.reqBody.isEmpty()) {
                    String b = t.reqBody.length() > 2000
                            ? t.reqBody.substring(0, 2000) + " ...[截断]"
                            : t.reqBody;
                    sb.append("      Body: ").append(b).append("\n");
                }
                sb.append("      -> ").append(t.rst ? "[RST/超时]" : ("HTTP " + t.status))
                  .append("  ").append(t.costMs).append("ms\n");
                if (!t.rst && !t.respText.isEmpty()) {
                    String body = t.respText.length() > 3000
                            ? t.respText.substring(0, 3000) + " ...[截断]"
                            : t.respText;
                    sb.append("      Resp: ").append(body).append("\n");
                }
            }
        }
        return sb.toString();
    }

    private static String rep(char c, int n) {
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) sb.append(c);
        return sb.toString();
    }
}
