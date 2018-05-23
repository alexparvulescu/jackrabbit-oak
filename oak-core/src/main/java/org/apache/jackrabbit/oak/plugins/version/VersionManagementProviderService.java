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
package org.apache.jackrabbit.oak.plugins.version;

import javax.annotation.Nonnull;

import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.spi.version.VersionManagementProvider;
import org.apache.jackrabbit.oak.spi.version.VersionManager;
import org.osgi.service.component.annotations.Component;

@Component(service = {VersionManagementProvider.class}, immediate = true)
public class VersionManagementProviderService implements VersionManagementProvider {

    @Override
    public VersionManager getReadOnlyVersionManager(@Nonnull Root root, @Nonnull NamePathMapper namePathMapper) {
        return ReadOnlyVersionManager.getInstance(root, namePathMapper);
    }
}