package com.jeescan.core;

import com.jeescan.checks.InfoLeak;
import com.jeescan.checks.JdbcTestConnection;
import com.jeescan.checks.Others;
import com.jeescan.checks.SqliErrorBased;
import com.jeescan.checks.SstiOthers;
import com.jeescan.checks.SstiQueryFieldBySql;

import java.util.ArrayList;
import java.util.List;

/** 检测器注册表。 */
public final class Registry {

    private Registry() {}

    public static List<Detector> all() {
        List<Detector> l = new ArrayList<>();

        // ---- SSTI / RCE ----
        l.add(new SstiQueryFieldBySql());                       // 1
        l.add(new JdbcTestConnection());                        // 2
        l.add(new SstiOthers.LoadTableData());                  // 3
        l.add(new SstiOthers.QurestSqlSsti());                  // 4

        // ---- SQLi ----
        // #5 queryTableData 必须用 GET（实测 POST 返回 405）；专用检测器见 Others.QueryTableData
        l.add(new Others.QueryTableData());

        l.add(new SqliErrorBased("6", "qurestSql SQLi",
                "/jmreport/qurestSql", "updatexml 报错", "critical", false,
                "apiSelectId/id 注入；随机标记 + 反例 + 二次确认",
                "POST", "jmreport/qurestSql",
                SqliErrorBased.Kind.PARAMS_JSON, "mysql"));

        l.add(new SstiOthers.GetDictItemsByTable());            // 7

        l.add(new Others.SqliShow());                           // 8
        l.add(new SqliErrorBased("9", "queryFieldBySql SQLi",
                "/jmreport/queryFieldBySql", "updatexml 报错", "high", false,
                "sql 参数报错注入；随机标记 + 反例",
                "POST", "jmreport/queryFieldBySql",
                SqliErrorBased.Kind.SQL_PARAM, "mysql"));

        l.add(new Others.SqliGetTotalData());                   // 10
        l.add(new Others.TimeBlind());                          // 11

        // ---- 上传 / 穿越 / SSRF ----
        l.add(new Others.Upload("12", "jmreport 未授权上传",
                "POST /jmreport/upload", "multipart", "high", false,
                "上传无害探针 txt，响应 success=true 即确认",
                "jmreport/upload", true));

        l.add(new Others.PathTraversalBypass("13", "commonController 路径穿越绕过",
                "POST /api/../commonController.do", "路径穿越", "high", false,
                "对比直连（被拦）与 ../ 绕过（通过）的差异",
                "commonController.do?parserXml", "upload"));

        l.add(new Others.Upload("14", "sys/common/upload 文件上传",
                "POST /sys/common/upload", "multipart", "high", true,
                "需要 Token；响应 success=true 即确认",
                "sys/common/upload", false));

        l.add(new Others.PathTraversalBypass("15", "jeecgFormDemoController SSRF",
                "POST /api/../jeecgFormDemoController.do", "SSRF/RCE", "critical", false,
                "对比直连与 ../ 绕过的鉴权差异",
                "jeecgFormDemoController.do?interfaceTest=", "ssrf"));

        // ---- 文件读取 ----
        l.add(new Others.FileRead("16", "imController 任意文件下载",
                "GET /chat/imController/showOrDownByurl.do", "路径遍历", "high", false,
                "fileUrl 参数可控；读取 /etc/passwd 验证，反例读不存在文件",
                "chat/imController/showOrDownByurl.do?fileUrl={P}", "fileUrl", true));

        l.add(new Others.FileRead("17", "P3 Biz Chat 任意文件读取",
                "GET /sys/p3/chat/download", "路径遍历", "high", false,
                "fileName 参数可控；同样的 /etc/passwd 差分验证",
                "sys/p3/chat/download?fileName={P}", "fileName", true));

        // ---- Aviator ----
        l.add(new Others.AviatorSaveShow());                    // 18

        // ---- Fastjson ----
        l.add(new Others.FastjsonJndi());                       // 19

        // ---- 信息泄露 ----
        l.add(new InfoLeak.QuerySysUser());                     // 20
        l.add(new InfoLeak.CheckOnlyUser());                    // 21
        l.add(new InfoLeak.Httptrace());                        // 22
        l.add(new InfoLeak.DataSourceList());                   // 23

        // ---- 默认口令 ----
        l.add(new Others.DefaultCred());                        // 24

        // ---- 密码重置 ----
        l.add(new InfoLeak.PasswordChange());                   // 25

        // ---- 目录遍历 ----
        l.add(new InfoLeak.FileTree());                         // 26

        // ---- 新增（对齐 JeecgGo Config.yaml 等公开工具） ----
        l.add(new Others.ColumnSqli());                         // 27 column 参数注入
        l.add(new Others.ParseSql());                           // 28 parseSql 注入
        l.add(new Others.SendMsgSsti());                        // 29 sendMsg 模板注入
        l.add(new Others.UploadImgByHttp());                    // 30 uploadImgByHttp SSRF
        l.add(new Others.AutoExport());                         // 31 auto/export 未授权导出
        l.add(new Others.ReportList());                         // 32 报表列表未授权枚举
        l.add(new InfoLeak.DictList());                         // 33 dict/list 未授权

        return l;
    }
}
