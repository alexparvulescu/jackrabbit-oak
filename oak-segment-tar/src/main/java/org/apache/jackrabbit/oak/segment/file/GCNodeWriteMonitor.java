/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.jackrabbit.oak.segment.file;

import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Monitors the compaction cycle and keeps a compacted nodes counter, in order
 * to provide a best effort progress log based on extrapolating the previous
 * size and node count and current size to deduce current node count.
 */
public class GCNodeWriteMonitor {

    private static final Logger log = LoggerFactory.getLogger(GCNodeWriteMonitor.class);

    public static final GCNodeWriteMonitor EMPTY = new GCNodeWriteMonitor(-1);

    /**
     * Flag to control behavior of timeouts, replace {@code Thread.sleep()} with
     * {@code Thread.yield()}
     */
    private static final boolean gcSleepYield = Boolean.getBoolean("oak.segment.compaction.gcSleepYield");

    /**
     * Number of nodes the monitor will log a message, -1 to disable
     */
    private long gcProgressLog;

    /**
     * Number of nodes the monitor will log a message, -1 to disable
     */
    private long sleepCycle = Long.getLong("oak.segment.compaction.gcSleepCycle", -1);

    /**
     * Ms to sleep at each cycle, -1 to disable
     */
    private long sleepMsPerCycle= Long.getLong("oak.segment.compaction.gcSleepMsPerCycle", -1);

    /**
     * Start timestamp of compaction (reset at each {@code init()} call).
     */
    private long start = 0;

    /**
     * Estimated nodes to compact per cycle (reset at each {@code init()} call).
     */
    private long estimated = -1;

    /**
     * Compacted nodes per cycle (reset at each {@code init()} call).
     */
    private long nodes;

    private boolean running = false;

    private long gcCount;

    /**
     * Enabled by the force compact call on the store, will skip any sleep settings
     */
    private boolean forceMode = false;

    public GCNodeWriteMonitor(long gcProgressLog) {
        this.gcProgressLog = gcProgressLog;
    }

    public synchronized void compacted() {
        nodes++;
        if (gcProgressLog > 0 && nodes % gcProgressLog == 0) {
            long ms = System.currentTimeMillis() - start;
            log.info("TarMK GC #{}: compacted {} nodes in {} ms.", gcCount, nodes, ms);
            start = System.currentTimeMillis();
        }
        if (!forceMode && sleepCycle > 0 && nodes % sleepCycle == 0) {
            if (gcSleepYield) {
                Thread.yield();
            } else {
                try {
                    TimeUnit.MILLISECONDS.sleep(sleepMsPerCycle);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    /**
     * @param gcCount
     *            current gc run
     * @param prevSize
     *            size from latest successful compaction
     * @param prevCompactedNodes
     *            number of nodes compacted during latest compaction operation
     * @param currentSize
     *            current repository size
     */
    public synchronized void init(long gcCount, long prevSize, long prevCompactedNodes, long currentSize) {
        this.gcCount = gcCount;
        if (prevCompactedNodes > 0) {
            estimated = (long) (((double) currentSize / prevSize) * prevCompactedNodes);
            log.info(
                    "TarMK GC #{}: estimated number of nodes to compact is {}, based on {} nodes compacted to {} bytes "
                            + "on disk in previous compaction and current size of {} bytes on disk.",
                    this.gcCount, estimated, prevCompactedNodes, prevSize, currentSize);
        } else {
            log.info("TarMK GC #{}: unable to estimate number of nodes for compaction, missing gc history.");
        }
        nodes = 0;
        start = System.currentTimeMillis();
        running = true;
        forceMode = false;
    }

    public synchronized void finished() {
        running = false;
    }

    /**
     * Compacted nodes in current cycle
     */
    public synchronized long getCompactedNodes() {
        return nodes;
    }

    /**
     * Estimated nodes to compact in current cycle. Can be {@code -1} if the
     * estimation could not be performed.
     */
    public synchronized long getEstimatedTotal() {
        return estimated;
    }

    /**
     * Estimated completion percentage. Can be {@code -1} if the estimation
     * could not be performed.
     */
    public synchronized int getEstimatedPercentage() {
        if (estimated > 0) {
            if (!running) {
                return 100;
            } else {
                return Math.min((int) (100 * ((double) nodes / estimated)), 99);
            }
        }
        return -1;
    }

    public synchronized boolean isCompactionRunning() {
        return running;
    }

    public long getGcProgressLog() {
        return gcProgressLog;
    }

    public void setGcProgressLog(long gcProgressLog) {
        this.gcProgressLog = gcProgressLog;
    }

    public synchronized long getSleepCycle() {
        return sleepCycle;
    }

    public synchronized void setSleepCycle(long sleepCycle) {
        this.sleepCycle = sleepCycle;
    }

    public synchronized long getSleepMsPerCycle() {
        return sleepMsPerCycle;
    }

    public synchronized void setSleepMsPerCycle(long sleepMsPerCycle) {
        this.sleepMsPerCycle = sleepMsPerCycle;
    }

    public synchronized void forceCompact() {
        this.forceMode = true;
    }
}
