package com.jeescan.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 极简 JSON 工具（零依赖）。
 * 只覆盖本工具需要的场景：构造请求体、从响应里取字段、判断字符串是否出现。
 */
public final class Json {

    private Json() {}

    /** 把 Java 字符串转成 JSON 字符串字面量（含引号）。 */
    public static String quote(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /** 构造扁平的 JSON 对象：{"k1":"v1","k2":"v2"}。 */
    public static String obj(String... kv) {
        if (kv.length % 2 != 0) throw new IllegalArgumentException("kv must be even");
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kv.length; i += 2) {
            if (i > 0) sb.append(',');
            sb.append(quote(kv[i])).append(':').append(quote(kv[i + 1]));
        }
        return sb.append('}').toString();
    }

    /** 构造 raw JSON 对象：直接拼 key:rawValue。 */
    public static String rawObj(String... kv) {
        if (kv.length % 2 != 0) throw new IllegalArgumentException("kv must be even");
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kv.length; i += 2) {
            if (i > 0) sb.append(',');
            sb.append(quote(kv[i])).append(':').append(kv[i + 1]);
        }
        return sb.append('}').toString();
    }

    // ---------------------------------------------------------------- 解析

    /** 解析成 Map / List / String / Number / Boolean / null；失败返回 null。 */
    public static Object parse(String text) {
        if (text == null) return null;
        String t = text.trim();
        if (t.isEmpty()) return null;
        try {
            P p = new P(t);
            Object v = p.value();
            p.skipWs();
            // 容忍尾随内容（有些响应会拼接 BOM 或换行）
            return v;
        } catch (Exception e) {
            return null;
        }
    }

    public static Map<String, Object> parseObject(String text) {
        Object o = parse(text);
        if (o instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) o;
            return m;
        }
        return null;
    }

    /** 按路径取字符串，如 get(json, "result.records")，支持数组下标 a[0].b。 */
    public static String str(String json, String path) {
        Object o = get(json, path);
        if (o == null) return null;
        return String.valueOf(o);
    }

    /** 按路径取原始对象。 */
    public static Object get(String json, String path) {
        Object cur = parse(json);
        if (cur == null) return null;
        if (path == null || path.isEmpty()) return cur;

        List<String> segs = splitPath(path);
        for (String seg : segs) {
            if (cur == null) return null;
            int idx = -1;
            String name = seg;
            int br = seg.indexOf('[');
            if (br >= 0 && seg.endsWith("]")) {
                name = seg.substring(0, br);
                try {
                    idx = Integer.parseInt(seg.substring(br + 1, seg.length() - 1));
                } catch (NumberFormatException ignored) {}
            }
            if (cur instanceof Map) {
                cur = ((Map<?, ?>) cur).get(name);
            } else if (cur instanceof List) {
                List<?> l = (List<?>) cur;
                if (idx < 0) idx = 0;
                cur = idx < l.size() ? l.get(idx) : null;
            } else {
                return null;
            }
            if (idx >= 0 && cur instanceof List) {
                List<?> l = (List<?>) cur;
                cur = idx < l.size() ? l.get(idx) : null;
            }
        }
        return cur;
    }

    private static List<String> splitPath(String path) {
        List<String> out = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c == '.') {
                if (sb.length() > 0) { out.add(sb.toString()); sb.setLength(0); }
            } else if (c == '[') {
                if (sb.length() > 0) { out.add(sb.toString()); sb.setLength(0); }
                int close = path.indexOf(']', i);
                if (close > i) {
                    out.add(path.substring(i, close + 1));
                    i = close;
                }
            } else {
                sb.append(c);
            }
        }
        if (sb.length() > 0) out.add(sb.toString());
        return out;
    }

    // ---------------------------------------------------------------- 递归下降

    private static final class P {
        private final String s;
        private int i;

        P(String s) { this.s = s; this.i = 0; }

        void skipWs() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\uFEFF') i++;
                else break;
            }
        }

        Object value() {
            skipWs();
            if (i >= s.length()) throw new IllegalStateException("eof");
            char c = s.charAt(i);
            switch (c) {
                case '{': return object();
                case '[': return array();
                case '"': return string();
                case 't': expect("true");  return Boolean.TRUE;
                case 'f': expect("false"); return Boolean.FALSE;
                case 'n': expect("null");  return null;
                default:  return number();
            }
        }

        private void expect(String w) {
            if (!s.startsWith(w, i)) throw new IllegalStateException("expect " + w);
            i += w.length();
        }

        private Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++; // {
            skipWs();
            if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
            while (i < s.length()) {
                skipWs();
                if (i < s.length() && s.charAt(i) == '}') { i++; break; }
                String k = string();
                skipWs();
                if (i < s.length() && s.charAt(i) == ':') i++;
                Object v = value();
                m.put(k, v);
                skipWs();
                if (i < s.length() && s.charAt(i) == ',') { i++; continue; }
                if (i < s.length() && s.charAt(i) == '}') { i++; break; }
                break;
            }
            return m;
        }

        private List<Object> array() {
            List<Object> l = new ArrayList<>();
            i++; // [
            skipWs();
            if (i < s.length() && s.charAt(i) == ']') { i++; return l; }
            while (i < s.length()) {
                skipWs();
                if (i < s.length() && s.charAt(i) == ']') { i++; break; }
                l.add(value());
                skipWs();
                if (i < s.length() && s.charAt(i) == ',') { i++; continue; }
                if (i < s.length() && s.charAt(i) == ']') { i++; break; }
                break;
            }
            return l;
        }

        private String string() {
            skipWs();
            if (i >= s.length() || s.charAt(i) != '"') throw new IllegalStateException("expect string");
            i++;
            StringBuilder sb = new StringBuilder();
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') break;
                if (c == '\\') {
                    if (i >= s.length()) break;
                    char e = s.charAt(i++);
                    switch (e) {
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'u':
                            if (i + 4 <= s.length()) {
                                sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                                i += 4;
                            }
                            break;
                        default: sb.append(e);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Number number() {
            int st = i;
            if (i < s.length() && (s.charAt(i) == '-' || s.charAt(i) == '+')) i++;
            boolean dec = false;
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c >= '0' && c <= '9') { i++; }
                else if (c == '.' || c == 'e' || c == 'E' || c == '-' || c == '+') { dec = true; i++; }
                else break;
            }
            String num = s.substring(st, i);
            if (num.isEmpty()) throw new IllegalStateException("bad number");
            try {
                if (dec) return Double.parseDouble(num);
                long v = Long.parseLong(num);
                if (v >= Integer.MIN_VALUE && v <= Integer.MAX_VALUE) return (int) v;
                return v;
            } catch (NumberFormatException e) {
                return 0;
            }
        }
    }
}
