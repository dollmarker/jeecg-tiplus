package com.jeescan.core;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * 零依赖 HTTP 客户端。
 *
 * 两个关键设计：
 * 1) RST 感知：WAF 命中会重置 TCP，这里捕获后标记 rst=true，且不抛异常，
 *    保证单项检测失败不会中断整轮扫描。
 * 2) 自动退避：连续 RST 后 sleep，避免把攻击机 IP 封死。
 */
public final class Http {

    private final String baseUrl;
    private final String token;
    private final Map<String, String> extraHeaders = new HashMap<>();
    private int timeoutMs = 20000;
    private int sleepMs = 0;
    private int rstStreak = 0;
    private boolean allowRedirect = false;
    private String userAgent =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            + "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    // ---- 代理 ----
    private java.net.Proxy proxy = null;
    private String proxyAuth = null;
    private String proxyType = "DIRECT";

    private static SSLSocketFactory trustAll;

    static {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, new java.security.SecureRandom());
            trustAll = ctx.getSocketFactory();
        } catch (Exception ignored) {}
    }

    public Http(String baseUrl) {
        this.baseUrl = trimRight(baseUrl);
        this.token = null;
    }

    public Http(String baseUrl, String token) {
        this.baseUrl = trimRight(baseUrl);
        this.token = token;
    }

    private static String trimRight(String s) {
        if (s == null) return "";
        String r = s.trim();
        while (r.endsWith("/")) r = r.substring(0, r.length() - 1);
        return r;
    }

    // ---------------------------------------------------------------- 配置

    public void setTimeout(int ms)          { this.timeoutMs = ms; }
    public void setSleep(int ms)            { this.sleepMs = ms; }
    public void setAllowRedirect(boolean b) { this.allowRedirect = b; }
    public void setUserAgent(String ua)     { this.userAgent = ua; }

    /**
     * 设置代理。
     *
     * @param type "HTTP" / "SOCKS" / "DIRECT"
     * @param host 代理主机，如 127.0.0.1
     * @param port 代理端口，如 8080
     * @param user 认证用户名（可空）
     * @param pass 认证密码（可空）
     */
    public void setProxy(String type, String host, int port, String user, String pass) {
        if (type == null || type.isEmpty() || "DIRECT".equalsIgnoreCase(type)
                || host == null || host.trim().isEmpty() || port <= 0) {
            this.proxy = null;
            this.proxyAuth = null;
            this.proxyType = "DIRECT";
            return;
        }
        this.proxyType = type.toUpperCase();
        this.proxy = new java.net.Proxy(
                "SOCKS".equals(this.proxyType) ? java.net.Proxy.Type.SOCKS : java.net.Proxy.Type.HTTP,
                new java.net.InetSocketAddress(host.trim(), port));
        if (user != null && !user.isEmpty()) {
            this.proxyAuth = user + ":" + (pass == null ? "" : pass);
            // SOCKS 代理的认证无法通过请求头传递，需要 JVM 级 Authenticator
            if ("SOCKS".equals(this.proxyType)) {
                final String u = user;
                final String p = pass == null ? "" : pass;
                java.net.Authenticator.setDefault(new java.net.Authenticator() {
                    @Override
                    protected java.net.PasswordAuthentication getPasswordAuthentication() {
                        return new java.net.PasswordAuthentication(u, p.toCharArray());
                    }
                });
            }
        } else {
            this.proxyAuth = null;
        }
    }

    public String getProxyDesc() {
        if (proxy == null) return "直连";
        java.net.InetSocketAddress a = (java.net.InetSocketAddress) proxy.address();
        return proxyType + " " + a.getHostString() + ":" + a.getPort()
                + (proxyAuth != null ? " (认证)" : "");
    }

    /**
     * 快速探测代理是否可用：连一个已知地址，看能否走通。
     * 返回 null 表示成功，否则返回错误描述。
     */
    public String testProxy(int timeoutMs) {
        if (proxy == null) return "未配置代理（直连）";
        java.net.Socket s = new java.net.Socket();
        try {
            s.connect(proxy.address(), timeoutMs);
            return null;
        } catch (Exception e) {
            return e.getClass().getSimpleName() + ": " + brief(e.getMessage());
        } finally {
            try { s.close(); } catch (Exception ignored) {}
        }
    }

    public void addHeader(String k, String v) { extraHeaders.put(k, v); }
    public void clearHeaders()              { extraHeaders.clear(); }
    public String getBaseUrl()               { return baseUrl; }
    public int getSleep()                    { return sleepMs; }
    public int getTimeout()                  { return timeoutMs; }

    /**
     * 拼接 URL。要求调用方传入"二级接口之后的路径"，
     * 本类不内置任何前缀（不自动加 jeecg-boot）。
     */
    public String url(String path) {
        if (path == null || path.isEmpty()) return baseUrl;
        if (path.startsWith("http://") || path.startsWith("https://")) return path;
        String p = path.startsWith("/") ? path.substring(1) : path;
        return baseUrl + "/" + p;
    }

    // ---------------------------------------------------------------- 请求

    public Resp get(String path) {
        return req("GET", path, null, null, null);
    }

    public Resp get(String path, Map<String, String> query) {
        return req("GET", path, query, null, null);
    }

    public Resp postJson(String path, String jsonBody) {
        return req("POST", path, null, jsonBody, "application/json");
    }

    public Resp postRaw(String path, byte[] body, String contentType) {
        return req("POST", path, null, body, contentType);
    }

    public Resp req(String method, String path, Map<String, String> query,
                    Object body, String contentType) {
        return req(method, path, query, body, contentType, null);
    }

    public Resp req(String method, String path, Map<String, String> query,
                    Object body, String contentType, Map<String, String> headers) {
        if (sleepMs > 0) {
            try { Thread.sleep(sleepMs); } catch (InterruptedException ignored) {}
        }

        String full = url(path);
        if (query != null && !query.isEmpty()) {
            StringBuilder sb = new StringBuilder(full);
            sb.append(full.contains("?") ? '&' : '?');
            boolean first = true;
            for (Map.Entry<String, String> e : query.entrySet()) {
                if (!first) sb.append('&');
                sb.append(UrlEnc.encode(e.getKey())).append('=').append(UrlEnc.encode(e.getValue()));
                first = false;
            }
            full = sb.toString();
        }

        long t0 = System.currentTimeMillis();
        HttpURLConnection conn = null;
        try {
            URL u = new URL(full);
            // 走代理（未配置时为 null，等同直连）
            conn = (HttpURLConnection) (proxy == null
                    ? u.openConnection()
                    : u.openConnection(proxy));
            if (conn instanceof HttpsURLConnection) {
                ((HttpsURLConnection) conn).setSSLSocketFactory(trustAll);
                ((HttpsURLConnection) conn).setHostnameVerifier((h, s) -> true);
            }
            // HTTP 代理认证头（SOCKS 认证由 JVM 的 Authenticator 负责，见 setProxy）
            if (proxyAuth != null && "HTTP".equals(proxyType)) {
                String enc = java.util.Base64.getEncoder().encodeToString(
                        proxyAuth.getBytes("UTF-8"));
                conn.setRequestProperty("Proxy-Authorization", "Basic " + enc);
            }
            conn.setRequestMethod(method);
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setInstanceFollowRedirects(allowRedirect);
            conn.setRequestProperty("User-Agent", userAgent);
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9");
            conn.setRequestProperty("Connection", "close");
            if (token != null && !token.isEmpty()) {
                conn.setRequestProperty("X-Access-Token", token);
            }
            for (Map.Entry<String, String> e : extraHeaders.entrySet()) {
                conn.setRequestProperty(e.getKey(), e.getValue());
            }
            if (headers != null) {
                for (Map.Entry<String, String> e : headers.entrySet()) {
                    conn.setRequestProperty(e.getKey(), e.getValue());
                }
            }

            if (body != null && !"GET".equalsIgnoreCase(method)) {
                byte[] data;
                if (body instanceof byte[]) {
                    data = (byte[]) body;
                } else {
                    data = String.valueOf(body).getBytes("UTF-8");
                }
                conn.setDoOutput(true);
                if (contentType != null) conn.setRequestProperty("Content-Type", contentType);
                conn.setFixedLengthStreamingMode(data.length);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(data);
                    os.flush();
                }
            }

            int code = conn.getResponseCode();
            InputStream is = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
            String text = readAll(is);
            Map<String, String> respHeaders = new HashMap<>();
            for (Map.Entry<String, java.util.List<String>> e : conn.getHeaderFields().entrySet()) {
                if (e.getKey() != null && e.getValue() != null && !e.getValue().isEmpty()) {
                    respHeaders.put(e.getKey().toLowerCase(), e.getValue().get(0));
                }
            }
            long cost = System.currentTimeMillis() - t0;
            rstStreak = 0;
            return new Resp(code, text, respHeaders, cost, false, null, full);

        } catch (IOException e) {
            // 被 WAF 重置 / 超时 —— 标记但不抛
            rstStreak++;
            int back = Math.min(3 * rstStreak, 15);
            if (rstStreak >= 2 && sleepMs >= 0) {
                try { Thread.sleep(back * 1000L); } catch (InterruptedException ignored) {}
            }
            long cost = System.currentTimeMillis() - t0;
            return new Resp(-1, "", new HashMap<>(), cost, true,
                    e.getClass().getSimpleName() + ": " + brief(e.getMessage()), full);
        } catch (Exception e) {
            long cost = System.currentTimeMillis() - t0;
            return new Resp(-1, "", new HashMap<>(), cost, true,
                    e.getClass().getSimpleName() + ": " + brief(e.getMessage()), full);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String brief(String s) {
        if (s == null) return "";
        return s.length() > 120 ? s.substring(0, 120) : s;
    }

    private static String readAll(InputStream is) throws IOException {
        if (is == null) return "";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
        is.close();
        String enc = "UTF-8";
        return new String(bos.toByteArray(), enc);
    }

    // ---------------------------------------------------------------- 响应

    public static final class Resp {
        public final int status;
        public final String text;
        public final Map<String, String> headers;
        public final long costMs;
        public final boolean rst;
        public final String err;
        public final String fullUrl;

        Resp(int status, String text, Map<String, String> headers,
             long costMs, boolean rst, String err, String fullUrl) {
            this.status = status;
            this.text = text == null ? "" : text;
            this.headers = headers;
            this.costMs = costMs;
            this.rst = rst;
            this.err = err;
            this.fullUrl = fullUrl;
        }

        public boolean ok() { return !rst && status >= 200 && status < 400; }

        public String header(String k) {
            return headers.get(k.toLowerCase());
        }

        public String brief(int n) {
            if (rst) return "[RST] " + (err == null ? "" : err);
            String t = text.replaceAll("\\s+", " ");
            return t.length() > n ? t.substring(0, n) : t;
        }

        public String brief() { return brief(200); }
    }

    // ---------------------------------------------------------------- URL 编码

    public static final class UrlEnc {
        public static String encode(String s) {
            if (s == null) return "";
            try {
                return java.net.URLEncoder.encode(s, "UTF-8");
            } catch (Exception e) {
                return s;
            }
        }
    }
}
