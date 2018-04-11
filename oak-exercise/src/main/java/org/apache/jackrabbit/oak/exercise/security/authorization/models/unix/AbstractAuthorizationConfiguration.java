package org.apache.jackrabbit.oak.exercise.security.authorization.models.unix;

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;

import org.apache.jackrabbit.oak.spi.commit.CommitHook;
import org.apache.jackrabbit.oak.spi.commit.MoveTracker;
import org.apache.jackrabbit.oak.spi.commit.ThreeWayConflictHandler;
import org.apache.jackrabbit.oak.spi.commit.ValidatorProvider;
import org.apache.jackrabbit.oak.spi.lifecycle.RepositoryInitializer;
import org.apache.jackrabbit.oak.spi.lifecycle.WorkspaceInitializer;
import org.apache.jackrabbit.oak.spi.security.ConfigurationBase;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.Context;
import org.apache.jackrabbit.oak.spi.security.authorization.AuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.xml.ProtectedItemImporter;

public abstract class AbstractAuthorizationConfiguration extends ConfigurationBase
        implements AuthorizationConfiguration {

    @Nonnull
    @Override
    public RestrictionProvider getRestrictionProvider() {
        return RestrictionProvider.EMPTY;
    }

    @Nonnull
    @Override
    public String getName() {
        return AuthorizationConfiguration.NAME;
    }

    @Nonnull
    @Override
    public ConfigurationParameters getParameters() {
        return ConfigurationParameters.EMPTY;
    }

    @Nonnull
    @Override
    public WorkspaceInitializer getWorkspaceInitializer() {
        return WorkspaceInitializer.DEFAULT;
    }

    @Nonnull
    @Override
    public RepositoryInitializer getRepositoryInitializer() {
        return RepositoryInitializer.DEFAULT;
    }

    @Nonnull
    @Override
    public List<? extends CommitHook> getCommitHooks(@Nonnull String workspaceName) {
        return Collections.emptyList();
    }

    @Nonnull
    @Override
    public List<? extends ValidatorProvider> getValidators(@Nonnull String workspaceName,
            @Nonnull Set<Principal> principals, @Nonnull MoveTracker moveTracker) {
        return Collections.emptyList();
    }

    @Nonnull
    @Override
    public List<ThreeWayConflictHandler> getConflictHandlers() {
        return Collections.emptyList();
    }

    @Nonnull
    @Override
    public List<ProtectedItemImporter> getProtectedItemImporters() {
        return Collections.emptyList();
    }

    @Nonnull
    @Override
    public Context getContext() {
        return Context.DEFAULT;
    }
}
