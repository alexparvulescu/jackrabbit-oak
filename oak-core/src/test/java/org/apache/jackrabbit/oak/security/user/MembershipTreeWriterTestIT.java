/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.jackrabbit.oak.security.user;

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.oak.api.Tree;
import org.junit.Test;

import com.google.common.collect.Maps;

public class MembershipTreeWriterTestIT extends MembershipBaseTest {

    @Test
    public void testBenchAddMembersUnique() throws Exception {
        assumeTrue(Boolean.getBoolean("MembershipWriterTestIT.testBenchAddMembersUnique"));

        Group grp = createGroup();

        // [TREE]
        // [ADD] #0 1000 times x 5 items. duration 36 ms.
        // [ADD] #1 1000 times x 5 items. duration 24 ms.
        // [ADD] #2 1000 times x 5 items. duration 17 ms.
        // [ADD] #3 1000 times x 5 items. duration 21 ms.
        // [ADD] #4 1000 times x 5 items. duration 15 ms.
        // [ADD] #5 1000 times x 5 items. duration 23 ms.
        // [ADD] #6 1000 times x 5 items. duration 13 ms.
        // [ADD] #7 1000 times x 5 items. duration 17 ms.
        // [ADD] #8 1000 times x 5 items. duration 17 ms.
        // [ADD] #9 1000 times x 5 items. duration 39 ms.
        // [ADD] #10 1000 times x 5 items. duration 46 ms.
        // [ADD] #11 1000 times x 5 items. duration 16 ms.
        // [ADD] #12 1000 times x 5 items. duration 16 ms.
        // [ADD] #13 1000 times x 5 items. duration 15 ms.
        // [ADD] #14 1000 times x 5 items. duration 21 ms.
        // [ADD] #15 1000 times x 5 items. duration 34 ms.
        // [ADD] #16 1000 times x 5 items. duration 13 ms.
        // [ADD] #17 1000 times x 5 items. duration 16 ms.
        // [ADD] #18 1000 times x 5 items. duration 19 ms.
        // [ADD] #19 1000 times x 5 items. duration 23 ms.
        // [ADD] #20 1000 times x 5 items. duration 20 ms.
        // [ADD] #21 1000 times x 5 items. duration 36 ms.
        // [ADD] #22 1000 times x 5 items. duration 33 ms.
        // [ADD] #23 1000 times x 5 items. duration 25 ms.
        // [ADD] #24 1000 times x 5 items. duration 29 ms.

        // [LIST]
        // [ADD] #0 1000 times x 5 items. duration 120 ms.
        // [ADD] #1 1000 times x 5 items. duration 200 ms.
        // [ADD] #2 1000 times x 5 items. duration 248 ms.
        // [ADD] #3 1000 times x 5 items. duration 347 ms.
        // [ADD] #4 1000 times x 5 items. duration 415 ms.
        // [ADD] #5 1000 times x 5 items. duration 476 ms.
        // [ADD] #6 1000 times x 5 items. duration 659 ms.
        // [ADD] #7 1000 times x 5 items. duration 736 ms.
        // [ADD] #8 1000 times x 5 items. duration 790 ms.
        // [ADD] #9 1000 times x 5 items. duration 860 ms.
        // [ADD] #10 1000 times x 5 items. duration 946 ms.
        // [ADD] #11 1000 times x 5 items. duration 1053 ms.
        // [ADD] #12 1000 times x 5 items. duration 1154 ms.
        // [ADD] #13 1000 times x 5 items. duration 1269 ms.
        // [ADD] #14 1000 times x 5 items. duration 1624 ms.
        // [ADD] #15 1000 times x 5 items. duration 1692 ms.
        // [ADD] #16 1000 times x 5 items. duration 1633 ms.
        // [ADD] #17 1000 times x 5 items. duration 1754 ms.
        // [ADD] #18 1000 times x 5 items. duration 1888 ms.
        // [ADD] #19 1000 times x 5 items. duration 2201 ms.
        // [ADD] #20 1000 times x 5 items. duration 2369 ms.
        // [ADD] #21 1000 times x 5 items. duration 2442 ms.
        // [ADD] #22 1000 times x 5 items. duration 2652 ms.
        // [ADD] #23 1000 times x 5 items. duration 2820 ms.
        // [ADD] #24 1000 times x 5 items. duration 2983 ms.

        int times = 1000;
        int size = 5;
        boolean useTreeWriter = GroupImpl.USE_NEW;

        MembershipWriter writer;
        if (useTreeWriter) {
            writer = new MembershipTreeWriter();
        } else {
            writer = new MembershipWriter();
        }

        Tree t = getTree(grp);

        for (int op = 0; op < 25; op++) {
            long total = 0;
            for (int c = 0; c < times; c++) {
                Map<String, String> idMap = Maps.newHashMap();
                for (int i = 0; i < size; i++) {
                    String memberId = "user" + System.currentTimeMillis() + "-" + c + "-" + i;
                    idMap.put(getContentID(memberId), memberId);
                }
                long start = System.currentTimeMillis();
                Set<String> res = writer.addMembers(t, idMap);
                long dur = System.currentTimeMillis() - start;
                total += dur;
                assertTrue("unable to add " + res, res.isEmpty());
            }
            System.err
                    .println("[ADD] #" + op + " " + times + " times x " + size + " items. duration " + total + " ms.");
        }
    }

    @Test
    public void testBenchAddMembersExisting() throws Exception {
        assumeTrue(Boolean.getBoolean("MembershipWriterTestIT.testBenchAddMembersExisting"));

        Group grp = createGroup();

        // [TREE]
        // [ADD] 10000 times x 5 samples | 50 items. duration 11ms (inlined)
        // [ADD] 10000 times x 5 samples | 150 items. duration 24ms
        // [ADD] 10000 times x 10 samples | 150 items. duration 42ms
        // [ADD] 10000 times x 50 samples | 150 items. duration 135ms
        // [ADD] 10000 times x 150 samples | 150 items. duration 250ms

        // [LIST]
        // [ADD] 10000 times x 5 samples | 50 items. duration 10ms (inlined)
        // [ADD] 10000 times x 5 samples | 150 items. duration 23ms
        // [ADD] 10000 times x 10 samples | 150 items. duration 30ms
        // [ADD] 10000 times x 50 samples | 150 items. duration 65ms
        // [ADD] 10000 times x 150 samples | 150 items. duration 140ms

        int batch = 150;
        int size = 150;
        boolean useTreeWriter = GroupImpl.USE_NEW;
        int times = 10000;

        MembershipWriter writer;
        if (useTreeWriter) {
            writer = new MembershipTreeWriter();
        } else {
            writer = new MembershipWriter();
        }

        // Setup adds all members beforehand
        Map<String, String> ids = Maps.newHashMap();
        String[] keys = new String[size];
        for (int i = 0; i < size; i++) {
            String memberId = "user" + System.currentTimeMillis() + "-" + i;
            String key = getContentID(memberId);
            ids.put(key, memberId);
            keys[i] = key;
        }
        assertTrue("unable to setup ", writer.addMembers(getTree(grp), ids).isEmpty());
        root.commit();
        Tree t = getTree(grp);

        long tg = 0;
        for (int cg = 1; cg <= 1000; cg++) {
            long total = 0;
            Random r = new Random();
            for (int c = 0; c < times; c++) {
                long start = System.currentTimeMillis();

                Map<String, String> sample = Maps.newHashMap();
                for (int i = 0; i < batch; i++) {
                    String key = keys[r.nextInt(size)];
                    sample.put(key, "" + i);
                }
                int samples = sample.size();

                Set<String> res = writer.addMembers(t, sample);

                long dur = System.currentTimeMillis() - start;
                total += dur;
                assertTrue("should not add any (" + res.size() + " vs " + samples + ")! " + res, res.size() == samples);
            }

            tg += total;
            long avg = tg / cg;
            System.err.println("[AddExisting] " + times + " times x " + batch + " samples | " + size
                    + " items. duration " + total + " ms. -- #" + cg + ": avg " + avg + " ms.");
        }
    }

}