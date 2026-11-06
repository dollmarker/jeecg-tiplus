package com.jeescan;

/**
 * 通用启动入口（不继承 Application）。
 *
 * 原因：当主类是 javafx.application.Application 的子类时，JVM 会走
 * JavaFX Launcher，即使 main() 里提前 return 也可能初始化 JavaFX 运行时，
 * 导致纯 CLI 模式被挂住。
 *
 * 所以把入口放在这个普通类里，由它按需分发：
 *   --cli  -> Cli（纯控制台，不碰 JavaFX）
 *   其他   -> FxApp（JavaFX 应用）
 */
public final class Launcher {

    public static void main(String[] args) {
        if (args.length > 0 && "--cli".equals(args[0])) {
            Cli.main(args);
        } else {
            FxApp.main(args);
        }
    }
}
