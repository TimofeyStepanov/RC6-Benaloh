package com.company.crypto.aesImpl;

import java.util.concurrent.atomic.AtomicLong;

public class CypherInformant {
    private final AtomicLong atomicLong = new AtomicLong(0);
    private final long fileLength;

    public CypherInformant(long fileLength) {
        this.fileLength = fileLength;
    }

    public void addProcessedBytes(long processedBytes) {
        //System.out.println(getPercentsOfProcessedBytes());
        atomicLong.addAndGet(processedBytes);
    }

    public int getPercentsOfProcessedBytes() {
        long numberOfProcessedBytes = atomicLong.get();
        if (numberOfProcessedBytes > fileLength) numberOfProcessedBytes = fileLength;
        return (int) (numberOfProcessedBytes * 100 / fileLength);
    }
}
