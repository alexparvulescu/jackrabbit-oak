package org.apache.jackrabbit.oak.exercise.security.authorization.models.unix;

import static org.apache.jackrabbit.JcrConstants.JCR_PRIMARYTYPE;
import static org.apache.jackrabbit.oak.api.Type.NAME;
import static org.apache.jackrabbit.oak.spi.nodetype.NodeTypeConstants.NT_OAK_UNSTRUCTURED;

import java.io.Console;
import java.io.PrintWriter;

import javax.jcr.GuestCredentials;
import javax.jcr.NoSuchWorkspaceException;
import javax.jcr.RepositoryException;
import javax.jcr.SimpleCredentials;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginException;

import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.oak.InitialContent;
import org.apache.jackrabbit.oak.Oak;
import org.apache.jackrabbit.oak.api.CommitFailedException;
import org.apache.jackrabbit.oak.api.ContentRepository;
import org.apache.jackrabbit.oak.api.ContentSession;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.commons.PathUtils;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.plugins.commit.ConflictValidatorProvider;
import org.apache.jackrabbit.oak.plugins.commit.JcrConflictHandler;
import org.apache.jackrabbit.oak.plugins.index.property.PropertyIndexEditorProvider;
import org.apache.jackrabbit.oak.plugins.index.property.PropertyIndexProvider;
import org.apache.jackrabbit.oak.plugins.index.reference.ReferenceEditorProvider;
import org.apache.jackrabbit.oak.plugins.index.reference.ReferenceIndexProvider;
import org.apache.jackrabbit.oak.plugins.name.NamespaceEditorProvider;
import org.apache.jackrabbit.oak.plugins.nodetype.TypeEditorProvider;
import org.apache.jackrabbit.oak.plugins.tree.RootProvider;
import org.apache.jackrabbit.oak.plugins.tree.TreeProvider;
import org.apache.jackrabbit.oak.plugins.tree.TreeUtil;
import org.apache.jackrabbit.oak.plugins.tree.impl.RootProviderService;
import org.apache.jackrabbit.oak.plugins.tree.impl.TreeProviderService;
import org.apache.jackrabbit.oak.plugins.version.VersionHook;
import org.apache.jackrabbit.oak.security.authorization.composite.CompositeAuthorizationConfiguration;
import org.apache.jackrabbit.oak.security.internal.SecurityProviderBuilder;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authentication.ConfigurationUtil;
import org.apache.jackrabbit.oak.spi.security.authorization.AuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.security.user.UserConfiguration;
import org.apache.jackrabbit.oak.spi.security.user.UserConstants;
import org.apache.jackrabbit.oak.spi.security.user.util.UserUtil;

import com.google.common.collect.Iterables;

/**
 * 
 * mvn exec:java
 * -Dexec.mainClass="org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.Main"
 * -Dexec.classpathScope="test"
 *
 */
public class Main {

    private final Console console;
    private final RootProvider rootProvider = new RootProviderService();
    private final TreeProvider treeProvider = new TreeProviderService();
    private final SecurityProvider securityProvider;
    private final ContentRepository contentRepository;
    private final String adminId;

    private ContentSession session;
    private String path = PathUtils.ROOT_PATH;

    public Main() {
        console = System.console();
        if (console == null) {
            System.err.println("No console.");
            System.exit(1);
        }

        securityProvider = initSecurityProvider();
        Oak oak = new Oak().with(new InitialContent()).with(new VersionHook())
                .with(JcrConflictHandler.createJcrConflictHandler()).with(new NamespaceEditorProvider())
                .with(new ReferenceEditorProvider()).with(new ReferenceIndexProvider())
                .with(new PropertyIndexEditorProvider()).with(new PropertyIndexProvider())
                .with(new TypeEditorProvider()).with(new ConflictValidatorProvider()).with(securityProvider);
        Configuration.setConfiguration(ConfigurationUtil.getDefaultConfiguration(ConfigurationParameters.EMPTY));
        contentRepository = oak.createContentRepository();

        adminId = UserUtil.getAdminId(securityProvider.getConfiguration(UserConfiguration.class).getParameters());
        doLogout();
    }

    protected SecurityProvider initSecurityProvider() {
        ConfigurationParameters params = ConfigurationParameters.of(UserConfiguration.NAME, ConfigurationParameters
                .of(UserConstants.PARAM_USER_PATH, "/home/users", UserConstants.PARAM_GROUP_PATH, "/home/groups"));

        SecurityProvider sp = SecurityProviderBuilder.newBuilder().with(params).withRootProvider(rootProvider)
                .withTreeProvider(treeProvider).build();

        FauxUnixAuthorizationConfiguration fauxUnix = new FauxUnixAuthorizationConfiguration();
        fauxUnix.setSecurityProvider(sp);
        fauxUnix.setRootProvider(rootProvider);
        fauxUnix.setTreeProvider(treeProvider);

        CompositeAuthorizationConfiguration ac = (CompositeAuthorizationConfiguration) sp
                .getConfiguration(AuthorizationConfiguration.class);
        ac.setDefaultConfig(fauxUnix);

        return sp;
    }

    private UserManager getUserManager(Root root) {
        return securityProvider.getConfiguration(UserConfiguration.class).getUserManager(root, NamePathMapper.DEFAULT);
    }

    private String getUserId() {
        return session.getAuthInfo().getUserID();
    }

    private boolean isAdmin() {
        return adminId.equals(session.getAuthInfo().getUserID());
    }

    private static void safeCommit(Root root, Console console) {
        try {
            root.commit();
        } catch (CommitFailedException e) {
            console.writer().println("Err: " + e.getMessage());
            root.refresh();
        }
    }

    private static String buildPath(String path, String p) {
        if (PathUtils.denotesRoot(p)) {
            return p;
        }

        if (p.charAt(p.length() - 1) == '/') {
            p = p.substring(0, p.length() - 1);
        }
        if (PathUtils.denotesCurrent(p)) {
            return path;
        }

        if (p.contains(".")) {
            String r = path;
            for (String e : PathUtils.elements(p)) {
                if (PathUtils.denotesParent(e)) {
                    r = PathUtils.denotesRoot(r) ? PathUtils.ROOT_PATH : PathUtils.getParentPath(r);
                    continue;
                } else if (!PathUtils.denotesCurrent(e)) {
                    r = PathUtils.concat(r, e);
                }
            }
            return r;
        } else if (PathUtils.isAbsolute(p)) {
            return p;
        } else {
            return PathUtils.concat(path, p);
        }
    }

    // Console Commands

    private void doHelp(String[] tkn) {
        PrintWriter w = console.writer();
        String h = null;
        if (tkn.length > 1) {
            h = tkn[1];
            console.writer().println("usage: " + h);
        }

        if (h == null) {
            w.println("Type `help name' to find out more about the function `name'.");
        }
        if (h == null || h.equals("help")) {
            w.println("    help             -- help screen");
        }
        if (h == null || h.equals("exit")) {
            w.println("    exit             -- exit console");
        }
        if (h == null || h.equals("whoami")) {
            w.println("    whoami           -- print user info");
        }
        if (h == null || h.equals("su")) {
            w.println("    su [user]        -- switch user (defaults to 'admin')");
        }
        if (h == null || h.equals("logout")) {
            w.println("    logout           -- logout");
        }
        if (h == null || h.equals("ls")) {
            w.println("    ls [path]        --");
        }
        if (h == null || h.equals("cd")) {
            w.println("    cd path          -- ");
        }
        if (h == null || h.equals("adduser")) {
            w.println("    adduser user     -- ");
        }
        if (h == null || h.equals("chown")) {
            w.println("    chown path user  -- ");
        }
        if (h == null || h.equals("add")) {
            w.println("    add path         -- add node (parent path must already exist)");
        }
        if (h == null || h.equals("rm")) {
            w.println("    rm path          -- remove node");
        }
        if (h == null || h.equals("padd")) {
            w.println("    padd name value  -- add property under current path");
        }
        if (h == null || h.equals("prm")) {
            w.println("    prm name         -- remove property under current path");
        }
        if (h == null || h.equals("print")) {
            w.println("    print [path]     -- print path info");
        }
        w.println();
    }

    private void doSu(String[] tkn) {
        String u = adminId;
        if (tkn.length > 1) {
            u = tkn[1];
        }
        char[] pass = console.readPassword("Password: ");
        try {
            session = contentRepository.login(new SimpleCredentials(u, pass), null);
        } catch (LoginException | NoSuchWorkspaceException e) {
            console.writer().println("Err: " + e.getMessage());
        }
    }

    private void doLogout() {
        try {
            session = contentRepository.login(new GuestCredentials(), null);
            console.writer().println("logout");
        } catch (LoginException | NoSuchWorkspaceException e) {
            console.writer().println("Err: " + e.getMessage());
        }
    }

    private void doLs(String[] tkn) {
        String path = this.path;
        if (tkn.length > 1) {
            path = buildPath(this.path, tkn[1]);
        }

        Tree t = session.getLatestRoot().getTree(path);
        if (t.exists()) {
            PrintWriter w = console.writer();

            if (!PathUtils.denotesRoot(path)) {
                String u0 = TreeUtil.getString(t, FauxUnixAuthorizationConfiguration.REP_USER);
                String p0 = TreeUtil.getString(t, FauxUnixAuthorizationConfiguration.REP_PERMISSIONS);
                w.println(String.format("%10s    %15s    %35s", p0, u0, "."));
            }

            t.getChildren().forEach(i -> {
                String u = TreeUtil.getString(i, FauxUnixAuthorizationConfiguration.REP_USER);
                String perms = TreeUtil.getString(i, FauxUnixAuthorizationConfiguration.REP_PERMISSIONS);
                w.println(String.format("%10s    %15s    %35s", perms, u, i.getName()));
            });

        } else {
            console.writer().println("ls: " + path + ": No such path");
        }
    }

    private void doCd(String[] tkn) {
        if (tkn.length <= 1) {
            console.writer().println("usage: cd path");
            return;
        }
        String path = buildPath(this.path, tkn[1]);
        Tree t = session.getLatestRoot().getTree(path);
        if (t.exists()) {
            this.path = t.getPath();
        } else {
            console.writer().println("cd: " + path + ": No such path");
        }
    }

    private void doAddUser(String[] tkn) {
        if (tkn.length == 1) {
            console.writer().println("usage: adduser user");
            return;
        }
        String u = tkn[1];
        if (!isAdmin()) {
            console.writer().println("Not admin!");
            return;
        }

        char[] pass = console.readPassword("[" + u + "]: ");
        Root root = session.getLatestRoot();
        try {
            User user = getUserManager(root).createUser(u, new String(pass));
            root.commit();

            // TODO turn this into an AuthorizableAction
            Tree home = root.getTree(user.getPath());
            home.setProperty(FauxUnixAuthorizationConfiguration.REP_USER, u);
            home.setProperty(FauxUnixAuthorizationConfiguration.REP_PERMISSIONS,
                    FauxUnixAuthorizationConfiguration.DEFAULT_PERMISSIONS);
            root.commit();

            console.writer().println("created " + user.getID());
        } catch (RepositoryException | CommitFailedException e) {
            console.writer().println("Err: " + e.getMessage());
            root.refresh();
        }
    }

    private void doChown(String[] tkn) {
        if (!isAdmin()) {
            console.writer().println("Not admin!");
            return;
        }

        if (tkn.length < 3) {
            console.writer().println("usage: chown path user");
            return;
        }
        String path = buildPath(this.path, tkn[1]);
        String user = tkn[2];

        Root root = session.getLatestRoot();
        Tree t = root.getTree(path);
        t.setProperty(FauxUnixAuthorizationConfiguration.REP_USER, user);
        t.setProperty(FauxUnixAuthorizationConfiguration.REP_PERMISSIONS,
                FauxUnixAuthorizationConfiguration.DEFAULT_PERMISSIONS);
        safeCommit(root, console);
    }

    private void doAdd(String[] tkn) {
        if (tkn.length <= 1) {
            console.writer().println("usage: add path");
            return;
        }
        String path = buildPath(this.path, tkn[1]);
        Root root = session.getLatestRoot();
        Tree parent = root.getTree(PathUtils.getParentPath(path));
        if (parent.exists()) {
            Tree child = parent.addChild(PathUtils.getName(path));
            child.setProperty(JCR_PRIMARYTYPE, NT_OAK_UNSTRUCTURED, NAME);
            safeCommit(root, console);
        } else {
            console.writer().println("add: " + parent.getPath() + ": No such path");
        }
    }

    private void doRm(String[] tkn) {
        if (tkn.length <= 1) {
            console.writer().println("usage: rm path");
            return;
        }
        String path = buildPath(this.path, tkn[1]);
        Root root = session.getLatestRoot();
        Tree t = session.getLatestRoot().getTree(path);
        if (t.exists()) {
            t.remove();
            safeCommit(root, console);
        } else {
            console.writer().println("rm: " + path + ": No such path");
        }
    }

    private void doPrintProperties(String[] tkn) {
        String path = this.path;
        if (tkn.length > 1) {
            path = buildPath(this.path, tkn[1]);
        }

        Root root = session.getLatestRoot();
        Tree tree = root.getTree(path);
        if (tree.exists()) {

            PrintWriter w = console.writer();

            // TODO

            tree.getProperties().forEach(p -> {
                String v;
                if (p.isArray()) {
                    v = Iterables.toString(p.getValue(Type.STRINGS));
                } else {
                    v = p.getValue(Type.STRING);
                }
                w.println(String.format("%15s    %s", p.getName(), v));
            });

        } else {
            console.writer().println("print: " + tree.getPath() + ": No such path");
        }
    }

    private void doAddProperty(String[] tkn) {
        if (tkn.length <= 2) {
            console.writer().println("usage: padd name value");
            return;
        }
        String name = tkn[1];
        String value = tkn[2];

        Root root = session.getLatestRoot();
        Tree tree = root.getTree(path);
        if (tree.exists()) {
            tree.setProperty(name, value);
            safeCommit(root, console);
        } else {
            console.writer().println("padd: " + tree.getPath() + ": No such path");
        }
    }

    private void doRmProperty(String[] tkn) {
        if (tkn.length <= 1) {
            console.writer().println("usage: prm name");
            return;
        }
        String name = tkn[1];
        Root root = session.getLatestRoot();
        Tree tree = root.getTree(path);
        if (tree.exists()) {
            tree.removeProperty(name);
            safeCommit(root, console);
        } else {
            console.writer().println("prm: " + tree.getPath() + ": No such path");
        }
    }

    private void repl() {
        PrintWriter w = console.writer();
        w.println("..............................................");
        w.println("..............................................");
        w.println(".......... Faux Unix Oak Playground ..........");
        w.println("..............................................");
        w.println("..............................................");
        w.println("try 'help' to get started");

        while (true) {
            String l = console.readLine("[" + getUserId() + ":" + path + "] ");
            String[] tkn = l.trim().split(" ");
            if (!runIt(tkn)) {
                return;
            }
        }
    }

    private boolean runIt(String[] tkn) {
        switch (tkn[0]) {
        case "":
            break;

        case "help":
            doHelp(tkn);
            break;

        case "exit":
            console.writer().println("bye!");
            return false;

        case "whoami":
            console.writer().println(getUserId());
            break;

        case "login":
            doSu(tkn);
            break;

        case "su":
            doSu(tkn);
            break;

        case "logout":
            doLogout();
            break;

        case "adduser":
            doAddUser(tkn);
            break;

        case "chown":
            doChown(tkn);
            break;

        case "ls":
            doLs(tkn);
            break;

        case "cd":
            doCd(tkn);
            break;

        case "add":
            doAdd(tkn);
            break;

        case "rm":
            doRm(tkn);
            break;

        case "padd":
            doAddProperty(tkn);
            break;

        case "prm":
            doRmProperty(tkn);
            break;

        case "print":
            doPrintProperties(tkn);
            break;

        default:
            console.writer().println(tkn[0] + ": command not found");
            break;
        }
        return true;
    }

    public static void main(String[] args) throws Exception {
        new Main().repl();
    }
}
