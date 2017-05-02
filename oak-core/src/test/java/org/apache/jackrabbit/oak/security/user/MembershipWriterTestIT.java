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

public class MembershipWriterTestIT extends MembershipBaseTest {

    @Test
    public void testBenchAddMembersUnique() throws Exception {
        assumeTrue(Boolean.getBoolean("MembershipWriterTestIT.testBenchAddMembersUnique"));

        Group grp = createGroup();

        // [TREE]
        // [ADD] 1000 times x 5 items. duration 35 ms.
        // [ADD] 1000 times x 50 items. duration 532 ms. // TODO
        // [ADD] 1000 times x 500 items. duration 4982 ms. // TODO

        // [LIST]
        // [ADD] 1000 times x 5 items. duration 156 ms. // TODO
        // [ADD] 1000 times x 50 items. duration 777 ms. // TODO
        // [ADD] 1000 times x 500 items. duration 11557 ms. // TODO

        int times = 1000;
        int size = 5;
        boolean useTreeWriter = false;

        MembershipWriter writer = new MembershipWriter(useTreeWriter);
        Tree t = getTree(grp);

        while (true) {
            long total = 0;
            for (int c = 0; c < times; c++) {
                long start = System.currentTimeMillis();

                Map<String, String> idMap = Maps.newHashMap();
                for (int i = 0; i < size; i++) {
                    String memberId = "user" + System.currentTimeMillis() + "-" + c + "-" + i;
                    idMap.put(getContentID(memberId), memberId);
                }
                Set<String> res = writer.addMembers(t, idMap);

                long dur = System.currentTimeMillis() - start;
                total += dur;
                assertTrue("unable to add " + res, res.isEmpty());
            }
            System.err.println("[ADD] " + times + " times x " + size + " items. duration " + total + " ms.");
        }
    }

    @Test
    public void testBenchAddMembersExisting() throws Exception {
        assumeTrue(Boolean.getBoolean("MembershipWriterTestIT.testBenchAddMembersExisting"));

        Group grp = createGroup();

        // [TREE]
        // [ADD] 10000 times x 5 samples | 50 items. duration 18ms. (inlined as
        // a mvp)
        // [ADD] 10000 times x 5 samples | 150 items. duration 40ms.
        // [ADD] 10000 times x 50 samples | 150 items. duration 230ms.
        // [ADD] 10000 times x 150 samples | 150 items. duration 400ms.

        // [LIST]
        // [ADD] 10000 times x 5 samples | 50 items. duration 10 ms. (inlined as
        // a mvp)
        // [ADD] 10000 times x 5 samples | 150 items. duration 25 ms.
        // [ADD] 10000 times x 50 samples | 150 items. duration 70ms.
        // [ADD] 10000 times x 150 samples | 150 items. duration 140ms.

        int batch = 5;
        int size = 150;
        boolean useTreeWriter = true;
        int times = 10000;

        MembershipWriter writer = new MembershipWriter(useTreeWriter);

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

        while (true) {
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
                assertTrue("should not add any (" + res.size() + " vs " + samples + ")! ", res.size() == samples);
            }

            System.err.println("[AddExisting] " + times + " times x " + batch + " samples | " + size
                    + " items. duration " + total + " ms.");
        }
    }

}