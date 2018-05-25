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
package org.apache.jackrabbit.oak.spi.security.authorization;

import static org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants.NT_REP_PRIVILEGES;
import static org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants.REP_NEXT;
import static org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants.REP_PRIVILEGES;

import java.security.Principal;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.jcr.security.AccessControlManager;

import org.apache.jackrabbit.JcrConstants;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.spi.lifecycle.RepositoryInitializer;
import org.apache.jackrabbit.oak.spi.security.SecurityConfiguration;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.OpenPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.state.NodeBuilder;

/**
 * This class implements an {@link AuthorizationConfiguration} which grants
 * full access to any {@link javax.security.auth.Subject}.
 */
public class OpenAuthorizationConfiguration extends SecurityConfiguration.Default
        implements AuthorizationConfiguration {

    @Nonnull
    @Override
    public AccessControlManager getAccessControlManager(@Nonnull Root root, @Nonnull NamePathMapper namePathMapper) {
        throw new UnsupportedOperationException();
    }

    @Nonnull
    @Override
    public RestrictionProvider getRestrictionProvider() {
        throw new UnsupportedOperationException();
    }

    @Nonnull
    @Override
    public PermissionProvider getPermissionProvider(@Nonnull Root root, @Nonnull String workspaceName, @Nonnull Set<Principal> principals) {
        return OpenPermissionProvider.getInstance();
    }

    @Override
    public RepositoryInitializer getRepositoryInitializer() {
        return new OpenAuthorizationInitializer();
    }

    private static class OpenAuthorizationInitializer implements RepositoryInitializer {
        @Override
        public void initialize(NodeBuilder builder) {
            NodeBuilder system = builder.getChildNode(JcrConstants.JCR_SYSTEM);
            if (system.exists() && !system.hasChildNode(REP_PRIVILEGES)) {
                NodeBuilder privileges = system.child(REP_PRIVILEGES);
                privileges.setProperty(JcrConstants.JCR_PRIMARYTYPE, NT_REP_PRIVILEGES, Type.NAME);
                privileges.setProperty(REP_NEXT, 0l);
            }
        }
    }
}
