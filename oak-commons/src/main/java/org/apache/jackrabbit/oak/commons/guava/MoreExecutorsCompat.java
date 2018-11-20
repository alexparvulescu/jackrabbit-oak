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
package org.apache.jackrabbit.oak.commons.guava;

import java.lang.reflect.Method;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;

import com.google.common.util.concurrent.MoreExecutors;

public class MoreExecutorsCompat {

    //
    // Guava 15.0 -> 23.x breaking changes around MoreExecutors:
    // - #directExecutor replaces #sameThreadExecutor;
    // - #newDirectExecutorService replaces #sameThreadExecutor
    //

    private static Method directExecutor;
    private static Method directExecutorService;
    static {
        try {
            directExecutor = MoreExecutors.class.getDeclaredMethod("directExecutor");
        } catch (Exception e) {
            try {
                directExecutor = MoreExecutors.class.getDeclaredMethod("sameThreadExecutor");
            } catch (Exception e1) {
                throw new IllegalStateException("Unable to identify 'directExecutor' method.", e1);
            }
        }
        try {
            directExecutorService = MoreExecutors.class.getDeclaredMethod("newDirectExecutorService");
        } catch (Exception e) {
            try {
                directExecutorService = MoreExecutors.class.getDeclaredMethod("sameThreadExecutor");
            } catch (Exception e1) {
                throw new IllegalStateException("Unable to identify 'newDirectExecutorService' method.", e1);
            }
        }
    }

    public static Executor directExecutor() {
        try {
            return (Executor) directExecutor.invoke(null);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public static ExecutorService directExecutorService() {
        try {
            return (ExecutorService) directExecutorService.invoke(null);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}
