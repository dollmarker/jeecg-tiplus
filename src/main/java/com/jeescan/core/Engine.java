package com.jeescan.core;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/** 扫描引擎：串行执行检测器，可中断。 */
public final class Engine {

    public interface Listener {
        void onStart(Detector d, int index, int total);
        void onDone(Result r, int index, int total);
        void onLog(String line);
        void onFinish(List<Result> results);
    }

    private volatile boolean stop = false;

    public void stop() { stop = true; }
    public boolean isStopped() { return stop; }

    public List<Result> run(List<Detector> detectors, Detector.Ctx ctx,
                            Listener listener) {
        List<Result> out = new ArrayList<>();
        int total = detectors.size();
        int i = 0;
        for (Detector d : detectors) {
            if (stop) {
                if (listener != null) listener.onLog("[!] 已被用户中断\n");
                break;
            }
            i++;
            if (listener != null) listener.onStart(d, i, total);
            Result r = null;
            try {
                d.getClass(); // touch
                long t0 = System.currentTimeMillis();
                r = d.run(ctx);
                if (r == null) {
                    r = d.newResult();
                    r.set(Result.State.ERROR, "检测器返回 null");
                }
                r.endMs = System.currentTimeMillis();
                r.startMs = t0;
                out.add(r);
            } catch (Throwable t) {
                r = d.newResult();
                r.set(Result.State.ERROR, "检测异常: " + t.getClass().getSimpleName()
                        + " " + (t.getMessage() == null ? "" : t.getMessage()));
                r.endMs = System.currentTimeMillis();
                out.add(r);
            }
            if (listener != null) listener.onDone(r, i, total);
        }
        if (listener != null) listener.onFinish(out);
        return out;
    }
}
