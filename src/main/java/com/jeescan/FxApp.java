package com.jeescan;

import com.jeescan.ui.MainView;
import javafx.application.Application;
import javafx.stage.Stage;

/**
 * JavaFX 应用。
 *
 * 样式：不加载任何自定义 CSS，不调用 setStyle()，
 * 完全使用 JavaFX 内置 Modena 主题的默认外观
 * （默认字体字号、1px 浅灰边框、白底，无主题色/渐变/阴影）。
 */
public class FxApp extends Application {

    @Override
    public void start(Stage stage) {
        stage.setTitle("jeecgboot-tiplus 漏洞检测 by dollmarker v1.0");

        MainView view = new MainView(stage);
        stage.setScene(view.build());
        stage.setMinWidth(1080);
        stage.setMinHeight(680);
        stage.show();

        // 关闭窗口时结束 JVM（避免后台扫描线程挂住）
        stage.setOnCloseRequest(e -> System.exit(0));
    }

    public static void main(String[] args) {
        launch(args);
    }
}
