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
package org.apache.jackrabbit.oak.exercise.security.authorization.models.unix;

import static org.apache.jackrabbit.oak.spi.security.RegistrationConstants.OAK_SECURITY_NAME;

import java.util.Collections;
import java.util.List;

import javax.jcr.RepositoryException;

import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.user.action.AbstractAuthorizableAction;
import org.apache.jackrabbit.oak.spi.security.user.action.AuthorizableAction;
import org.apache.jackrabbit.oak.spi.security.user.action.AuthorizableActionProvider;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(service = AuthorizableActionProvider.class, property = OAK_SECURITY_NAME
        + "=org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizableActionProvider")
public class FauxUnixAuthorizableActionProvider implements AuthorizableActionProvider {

    @Override
    public List<? extends AuthorizableAction> getAuthorizableActions(SecurityProvider securityProvider) {
        return Collections.singletonList(new FauxUnixAuthorizableAction());
    }

    public static class FauxUnixAuthorizableAction extends AbstractAuthorizableAction {

        // XXX
        // - on user create set default permissions on home via
        // AuthorizableAction:
        // -- DefaultAuthorizableActionProvider injects an AccessControlAction
        // that is supposed to handle this
        // -- AccessControlAction needs to have USER_PRIVILEGE_NAMES configured
        // -- AccessControlAction only deals with 'JackrabbitAccessControlList'
        // and the faux impl does not provide it as such
        //
        // - how do I know if I need to run _this_ action or simply skip it?
        // is this dependent on the order of hooks

        private static final Logger log = LoggerFactory.getLogger(FauxUnixAuthorizableAction.class);

        @Override
        public void onCreate(User user, String password, Root root, NamePathMapper namePathMapper)
                throws RepositoryException {
            log.info("onCreate({})", user.getPath());
            Tree t = root.getTree(user.getPath());
            t.setProperty(FauxUnixAuthorizationConfiguration.REP_USER, user.getID());
        }
    }
}
