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
package org.apache.jackrabbit.oak.spi.security.authorization.cug.impl;

import static org.apache.jackrabbit.oak.spi.security.RegistrationConstants.OAK_SECURITY_NAME;

import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.jcr.RepositoryException;
import javax.jcr.security.AccessControlManager;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.plugins.memory.MemoryNodeStore;
import org.apache.jackrabbit.oak.plugins.name.NamespaceEditorProvider;
import org.apache.jackrabbit.oak.plugins.nodetype.TypeEditorProvider;
import org.apache.jackrabbit.oak.spi.commit.CommitHook;
import org.apache.jackrabbit.oak.spi.commit.CompositeEditorProvider;
import org.apache.jackrabbit.oak.spi.commit.EditorHook;
import org.apache.jackrabbit.oak.spi.commit.MoveTracker;
import org.apache.jackrabbit.oak.spi.commit.ValidatorProvider;
import org.apache.jackrabbit.oak.spi.lifecycle.RepositoryInitializer;
import org.apache.jackrabbit.oak.spi.mount.MountInfoProvider;
import org.apache.jackrabbit.oak.spi.mount.Mounts;
import org.apache.jackrabbit.oak.spi.namespace.NamespaceManagementProvider;
import org.apache.jackrabbit.oak.spi.nodetype.NodeTypeManagementProvider;
import org.apache.jackrabbit.oak.spi.nodetype.NodeTypeManager;
import org.apache.jackrabbit.oak.spi.security.CompositeConfiguration;
import org.apache.jackrabbit.oak.spi.security.ConfigurationBase;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.Context;
import org.apache.jackrabbit.oak.spi.security.SecurityConfiguration;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.AuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.security.authorization.cug.CugExclude;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.EmptyPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.state.ApplyDiff;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.apache.jackrabbit.oak.spi.state.NodeStore;
import org.apache.jackrabbit.oak.spi.version.VersionManagementProvider;
import org.apache.jackrabbit.oak.spi.xml.ProtectedItemImporter;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

@Component(metatype = true,
        label = "Apache Jackrabbit Oak CUG Configuration",
        description = "Authorization configuration dedicated to setup and evaluate 'Closed User Group' permissions.",
        policy = ConfigurationPolicy.REQUIRE)
@Service({AuthorizationConfiguration.class, SecurityConfiguration.class})
@Properties({
        @Property(name = CugConstants.PARAM_CUG_SUPPORTED_PATHS,
                label = "Supported Paths",
                description = "Paths under which CUGs can be created and will be evaluated.",
                cardinality = Integer.MAX_VALUE),
        @Property(name = CugConstants.PARAM_CUG_ENABLED,
                label = "CUG Evaluation Enabled",
                description = "Flag to enable the evaluation of the configured CUG policies.",
                boolValue = false),
        @Property(name = CompositeConfiguration.PARAM_RANKING,
                label = "Ranking",
                description = "Ranking of this configuration in a setup with multiple authorization configurations.",
                intValue = 200),
        @Property(name = OAK_SECURITY_NAME,
                propertyPrivate = true,
                value = "org.apache.jackrabbit.oak.spi.security.authorization.cug.impl.CugConfiguration")        
})
public class CugConfiguration extends ConfigurationBase implements AuthorizationConfiguration, CugConstants {

    /**
     * Reference to services implementing {@link org.apache.jackrabbit.oak.spi.security.authorization.cug.CugExclude}.
     */
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private CugExclude exclude;

    /**
     * Reference to service implementing {@link MountInfoProvider} to make the
     * CUG authorization model multiplexing aware.
     */
    @Reference
    private MountInfoProvider mountInfoProvider = Mounts.defaultMountInfoProvider();

    @Reference
    private VersionManagementProvider versionManagementProvider;

    @Reference
    private NamespaceManagementProvider namespaceManagementProvider;

    @Reference
    private NodeTypeManagementProvider nodeTypeManagementProvider;

    private Set<String> supportedPaths = ImmutableSet.of();

    @SuppressWarnings("UnusedDeclaration")
    public CugConfiguration() {
        super();
    }

    public CugConfiguration(@Nonnull SecurityProvider securityProvider) {
        super(securityProvider, securityProvider.getParameters(NAME));
    }

    @Nonnull
    @Override
    public AccessControlManager getAccessControlManager(@Nonnull Root root, @Nonnull NamePathMapper namePathMapper) {
        return new CugAccessControlManager(root, namePathMapper, getSecurityProvider(), supportedPaths);
    }

    @Nonnull
    @Override
    public RestrictionProvider getRestrictionProvider() {
        return RestrictionProvider.EMPTY;
    }

    @Nonnull
    @Override
    public PermissionProvider getPermissionProvider(@Nonnull Root root, @Nonnull String workspaceName, @Nonnull Set<Principal> principals) {
        ConfigurationParameters params = getParameters();
        boolean enabled = params.getConfigValue(CugConstants.PARAM_CUG_ENABLED, false);

        if (!enabled || supportedPaths.isEmpty() || getExclude().isExcluded(principals)) {
            return EmptyPermissionProvider.getInstance();
        } else {
            return new CugPermissionProvider(root, workspaceName, principals, supportedPaths, getSecurityProvider().getConfiguration(AuthorizationConfiguration.class).getContext(), getRootProvider(), getTreeProvider(), versionManagementProvider);
        }
    }

    @Nonnull
    @Override
    public String getName() {
        return AuthorizationConfiguration.NAME;
    }

    @Nonnull
    @Override
    public RepositoryInitializer getRepositoryInitializer() {
        return builder -> {
            NodeState base = builder.getNodeState();
            NodeStore store = new MemoryNodeStore(base);

            // TODO
            Root root = getRootProvider().createSystemRoot(store, 
                    new EditorHook(new CompositeEditorProvider(
//                            new NamespaceEditorProvider(),
                            //new TypeEditorProvider(true)
                            
                            )));
                    
                    
                    //null);
//                    new EditorHook(new CompositeEditorProvider(namespaceManagementProvider.getEditorProvider(), nodeTypeManagementProvider.getEditorProvider(true))));
            if (registerCugNodeTypes(root)) {
                NodeState target = store.getRoot();
                target.compareAgainstBaseState(base, new ApplyDiff(builder));
            }
        };
    }

    @Nonnull
    @Override
    public List<? extends CommitHook> getCommitHooks(@Nonnull String workspaceName) {
        return Collections.singletonList(new NestedCugHook());
    }

    @Nonnull
    @Override
    public List<? extends ValidatorProvider> getValidators(@Nonnull String workspaceName, @Nonnull Set<Principal> principals, @Nonnull MoveTracker moveTracker) {
        return ImmutableList.of(new CugValidatorProvider(nodeTypeManagementProvider));
    }

    @Nonnull
    @Override
    public List<ProtectedItemImporter> getProtectedItemImporters() {
        return Collections.<ProtectedItemImporter>singletonList(new CugImporter(mountInfoProvider));
    }

    @Nonnull
    @Override
    public Context getContext() {
        return CugContext.INSTANCE;
    }

    @Override
    public void setParameters(@Nonnull ConfigurationParameters config) {
        super.setParameters(config);
        supportedPaths = CugUtil.getSupportedPaths(config, mountInfoProvider);
    }

    //----------------------------------------------------< SCR Integration >---
    @SuppressWarnings("UnusedDeclaration")
    @Activate
    protected void activate(Map<String, Object> properties) {
        setParameters(ConfigurationParameters.of(properties));
    }

    @SuppressWarnings("UnusedDeclaration")
    @Modified
    protected void modified(Map<String, Object> properties) {
        activate(properties);
    }

    public void bindMountInfoProvider(MountInfoProvider mountInfoProvider) {
        this.mountInfoProvider = mountInfoProvider;
    }

    public void unbindMountInfoProvider(MountInfoProvider mountInfoProvider) {
        // set to null (and not default) to comply with OSGi lifecycle,
        // if the reference is unset it means the service is being deactivated
        this.mountInfoProvider = null;
    }

    public void bindVersionManagementProvider(VersionManagementProvider versionManagementProvider) {
        this.versionManagementProvider = versionManagementProvider;
    }

    public void unbindVersionManagementProvider(VersionManagementProvider versionManagementProvider) {
        this.versionManagementProvider = null;
    }

    public void bindNamespaceManagementProvider(NamespaceManagementProvider namespaceManagementProvider) {
        this.namespaceManagementProvider = namespaceManagementProvider;
    }

    public void unbindNamespaceManagementProvider(NamespaceManagementProvider namespaceManagementProvider) {
        this.namespaceManagementProvider = null;
    }

    public void bindNodeTypeManagementProvider(NodeTypeManagementProvider nodeTypeManagementProvider) {
        this.nodeTypeManagementProvider = nodeTypeManagementProvider;
    }

    public void unbindNodeTypeManagementProvider(NodeTypeManagementProvider nodeTypeManagementProvider) {
        this.nodeTypeManagementProvider = null;
    }

    public void bindExclude(CugExclude exclude) {
        this.exclude = exclude;
    }

    public void unbindExclude(CugExclude exclude) {
        this.exclude = null;
    }

    //--------------------------------------------------------------------------
    @Nonnull
    private CugExclude getExclude() {
        return (exclude == null) ? new CugExclude.Default() : exclude;
    }

    boolean registerCugNodeTypes(@Nonnull final Root root) {
        try {
            NodeTypeManager ntMgr = nodeTypeManagementProvider.getReadOnlyNodeTypeManager(root, NamePathMapper.DEFAULT);
            if (!ntMgr.hasNodeType(NT_REP_CUG_POLICY)) {
                try (InputStream stream = CugConfiguration.class.getResourceAsStream("cug_nodetypes.cnd")) {
                    nodeTypeManagementProvider.registerNodeTypes(root, stream, "cug node types");
                    return true;
                }
            }
        } catch (IOException | RepositoryException e) {
            throw new IllegalStateException("Unable to read cug node types", e);
        }
        return false;
    }
}