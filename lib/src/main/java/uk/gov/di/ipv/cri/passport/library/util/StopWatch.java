package uk.gov.di.ipv.cri.passport.library.util;

public class StopWatch {

    private long startTime = 0;

    public StopWatch() {
        // Intended
    }

    public void start() {
        startTime = System.currentTimeMillis();
    }

    public long stop() {
        return System.currentTimeMillis() - startTime;
    }
}
