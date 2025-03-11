package org.example.authorizationserver.util;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class SnowflakeIdGeneratorUtil {
    private static final long EPOCH = 1704067200000L; // Company's epoch = Monday, January 1, 2024 12:00:00 AM
    private static final long DATACENTER_ID_BITS = 5L;
    private static final long MACHINE_ID_BITS = 5L;
    private static final long SEQUENCE_BITS = 12L;
    private static final long MAX_DATACENTER_ID = ~(-1L << DATACENTER_ID_BITS);
    private static final long MAX_MACHINE_ID = ~(-1L << MACHINE_ID_BITS);
    private static final long SEQUENCE_MASK = ~(-1L << SEQUENCE_BITS);
    private final long datacenterId;
    private final long machineId;
    private final AtomicLong sequence = new AtomicLong(0L);
    private final AtomicLong lastTimestamp = new AtomicLong(-1L);
    private final ConcurrentHashMap<Long, AtomicLong> threadWaitCount = new ConcurrentHashMap<>();

    public SnowflakeIdGeneratorUtil(long datacenterId, long machineId) {
        this.datacenterId = datacenterId;
        this.machineId = machineId;
        if (datacenterId > MAX_DATACENTER_ID || datacenterId < 0) {
            throw new IllegalArgumentException("Datacenter ID can't be greater than " + MAX_DATACENTER_ID + " or less than 0");
        }
        if (machineId > MAX_MACHINE_ID || machineId < 0) {
            throw new IllegalArgumentException("Machine ID can't be greater than " + MAX_MACHINE_ID + " or less than 0");
        }
    }

    public synchronized long generateId() {
        long timestamp = System.currentTimeMillis();
        long lastTs = lastTimestamp.get();
        if (timestamp < lastTs) {
            throw new RuntimeException("Clock moved backwards. Refusing to generate id");
        }
        if (timestamp == lastTs) {
            long seq = sequence.incrementAndGet() & SEQUENCE_MASK;
            if (seq == 0) {
                timestamp = waitForNextMillis(lastTs);
            }
        } else {
            sequence.set(0L);
        }
        lastTimestamp.set(timestamp);
        return ((timestamp - EPOCH) << (DATACENTER_ID_BITS + MACHINE_ID_BITS + SEQUENCE_BITS))
                | (datacenterId << (MACHINE_ID_BITS + SEQUENCE_BITS))
                | (machineId << SEQUENCE_BITS)
                | sequence.get();
    }


    private long waitForNextMillis(long lastTimestamp) {
        long timestamp = System.currentTimeMillis();
        long waitCount = threadWaitCount.computeIfAbsent(lastTimestamp, k -> new AtomicLong(0)).incrementAndGet();
        while (timestamp <= lastTimestamp) {
            try {
                Thread.sleep(waitCount);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted while waiting for next millisecond", e);
            }
            timestamp = System.currentTimeMillis();
        }
        threadWaitCount.remove(lastTimestamp);
        return timestamp;
    }
}
