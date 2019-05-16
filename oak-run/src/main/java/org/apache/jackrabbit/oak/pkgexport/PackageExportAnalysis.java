package org.apache.jackrabbit.oak.pkgexport;

import java.io.IOException;
import java.net.URL;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.bcel.Repository;
import org.apache.bcel.classfile.AccessFlags;
import org.apache.bcel.classfile.ClassParser;
import org.apache.bcel.classfile.EmptyVisitor;
import org.apache.bcel.classfile.Field;
import org.apache.bcel.classfile.FieldOrMethod;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.classfile.Visitor;
import org.apache.bcel.generic.ArrayType;
import org.apache.bcel.generic.ObjectType;
import org.apache.bcel.generic.Type;
import org.apache.jackrabbit.oak.run.commons.Command;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PackageExportAnalysis implements Command {

    private static final Logger log = LoggerFactory.getLogger(PackageExportAnalysis.class);

    private static String[] whitelist = new String[] { "java", "org.apache.jackrabbit" };

    private static Set<String> OAK_PUBLIC_PACKAGES = new HashSet<String>(Arrays.asList(

            // oak-auth-external
            "org.apache.jackrabbit.oak.spi.security.authentication.external",
            "org.apache.jackrabbit.oak.spi.security.authentication.external.basic",

            // oak-authorization-cug
            "org.apache.jackrabbit.oak.spi.security.authorization.cug",

            // oak-authorization-principalbased
            "org.apache.jackrabbit.oak.spi.security.authorization.principalbased",

            // oak-blob-cloud-azure
            "org.apache.jackrabbit.oak.blob.cloud.azure.blobstorage",

            // oak-blob-cloud
            "org.apache.jackrabbit.oak.blob.cloud.s3.stats", "org.apache.jackrabbit.oak.blob.cloud.aws.s3",

            // oak-blob-plugins
            "org.apache.jackrabbit.oak.plugins.blob", "org.apache.jackrabbit.oak.plugins.blob.datastore",
            "org.apache.jackrabbit.oak.plugins.blob.datastore.directaccess",

            // oak-blob
            "org.apache.jackrabbit.oak.spi.blob", "org.apache.jackrabbit.oak.spi.blob.split",
            "org.apache.jackrabbit.oak.spi.blob.stats",

            // oak-commons
            "org.apache.jackrabbit.oak.commons", "org.apache.jackrabbit.oak.commons.cache",
            "org.apache.jackrabbit.oak.commons.concurrent", "org.apache.jackrabbit.oak.commons.io",
            "org.apache.jackrabbit.oak.commons.json", "org.apache.jackrabbit.oak.commons.sort",

            // oak-core-spi
            "org.apache.jackrabbit.oak.cache", "org.apache.jackrabbit.oak.commons.jmx",
            "org.apache.jackrabbit.oak.namepath", "org.apache.jackrabbit.oak.osgi",
            "org.apache.jackrabbit.oak.spi.descriptors", "org.apache.jackrabbit.oak.spi.gc",
            "org.apache.jackrabbit.oak.spi.lock", "org.apache.jackrabbit.oak.spi.mount",
            "org.apache.jackrabbit.oak.spi.namespace", "org.apache.jackrabbit.oak.spi.nodetype",
            "org.apache.jackrabbit.oak.spi.observation", "org.apache.jackrabbit.oak.spi.version",
            "org.apache.jackrabbit.oak.spi.whiteboard", "org.apache.jackrabbit.oak.stats",

            // oak-core
            "org.apache.jackrabbit.oak", "org.apache.jackrabbit.oak.namepath.impl",
            "org.apache.jackrabbit.oak.plugins.commit", "org.apache.jackrabbit.oak.plugins.identifier",
            "org.apache.jackrabbit.oak.plugins.index", "org.apache.jackrabbit.oak.plugins.index.aggregate",
            "org.apache.jackrabbit.oak.plugins.index.fulltext", "org.apache.jackrabbit.oak.plugins.index.importer",
            "org.apache.jackrabbit.oak.plugins.index.property",
            "org.apache.jackrabbit.oak.plugins.index.property.strategy",
            "org.apache.jackrabbit.oak.plugins.index.reference", "org.apache.jackrabbit.oak.plugins.lock",
            "org.apache.jackrabbit.oak.plugins.migration", "org.apache.jackrabbit.oak.plugins.migration.report",
            "org.apache.jackrabbit.oak.plugins.name", "org.apache.jackrabbit.oak.plugins.nodetype",
            "org.apache.jackrabbit.oak.plugins.nodetype.write", "org.apache.jackrabbit.oak.plugins.observation",
            "org.apache.jackrabbit.oak.plugins.observation.filter", "org.apache.jackrabbit.oak.plugins.tree.factories",
            "org.apache.jackrabbit.oak.plugins.version",

            // oak-jcr
            "org.apache.jackrabbit.oak.jcr", "org.apache.jackrabbit.oak.jcr.observation.filter",

            // oak-lucene
            "org.apache.jackrabbit.oak.plugins.index.lucene", "org.apache.jackrabbit.oak.plugins.index.lucene.score",
            "org.apache.jackrabbit.oak.plugins.index.lucene.spi", "org.apache.jackrabbit.oak.plugins.index.lucene.util",

            // oak-query-spi
            "org.apache.jackrabbit.oak.query.facet", "org.apache.jackrabbit.oak.spi.query",
            "org.apache.jackrabbit.oak.spi.query.fulltext",

            // oak-security-spi
            "org.apache.jackrabbit.oak.plugins.tree",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security.authentication",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security.authentication.callback",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security.authentication.credentials",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security.authentication.token",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security.authorization",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security.authorization.permission",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security.authorization.restriction",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security.principal",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security.privilege",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security.user",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security.user.action",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.security.user.util",
            "oak-security-spi.src.main.java.org.apache.jackrabbit.oak.spi.xml",

            // oak-segment-tar
            "org.apache.jackrabbit.oak.segment.spi.monitor", "org.apache.jackrabbit.oak.segment.spi.persistence",

            // oak-store-composite
            "org.apache.jackrabbit.oak.composite", "org.apache.jackrabbit.oak.composite.checks",

            // oak-store-document
            "org.apache.jackrabbit.oak.plugins.document.spi",

            // oak-store-spi
            "org.apache.jackrabbit.oak.json", "org.apache.jackrabbit.oak.plugins.memory",
            "org.apache.jackrabbit.oak.plugins.value", "org.apache.jackrabbit.oak.plugins.value.jcr",
            "org.apache.jackrabbit.oak.spi.cluster", "org.apache.jackrabbit.oak.spi.commit",
            "org.apache.jackrabbit.oak.spi.filter", "org.apache.jackrabbit.oak.spi.lifecycle",
            "org.apache.jackrabbit.oak.spi.state"));

    @Override
    public void execute(String... arg0) throws Exception {
        Enumeration<URL> en = Thread.currentThread().getContextClassLoader().getResources("org/apache/jackrabbit/oak");
        while (en.hasMoreElements()) {
            URL u = en.nextElement();
            if (u.getProtocol().equals("file")) {
                continue;
            }
            log.info("Analyzing jar {}.", u.getFile());

            FileSystem fs = FileSystems.newFileSystem(u.toURI(), Collections.emptyMap());
            for (Path p : fs.getRootDirectories()) {

                Files.walkFileTree(p, new SimpleFileVisitor<Path>() {

                    @Override
                    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                        visitPackage(dir);
                        return FileVisitResult.CONTINUE;
                    }
                });
            }
        }
    }

    private void visitPackage(Path p) throws IOException {
        if (!p.startsWith("/org/apache/jackrabbit/oak")) {
            return;
        }
        // /org/apache/jackrabbit/oak/spi/security/principal/ ->
        // org.apache.jackrabbit.oak.spi.security.principal
        String ps = p.toString();
        String pkg = ps.substring(1, ps.length() - 1).replaceAll("/", ".");
        log.debug("Analyzing package {}", pkg);

        String packageInfo = p.toString() + "package-info.class";
        Set<String> files = Files.list(p).map(q -> q.toString()).filter(r -> r.endsWith(".class"))
                .collect(Collectors.toSet());
        if (files.remove(packageInfo) || OAK_PUBLIC_PACKAGES.contains(pkg)) {
            analizePackage(files);
        }
    }

    private void analizePackage(Set<String> files) throws IOException {
        if (files.isEmpty()) {
            return;
        }

        for (String fsF : files) {
            // /org/apache/jackrabbit/oak/OakInitializer.class ->
            // org.apache.jackrabbit.oak.OakInitializer
            String f = fsF.substring(1, fsF.length() - 6);
            log.debug("Analyzing class {}", f);

            Visitor visitor = new ClassVisitor(reportPredicate());
            JavaClass jc;
            try {
                jc = getJavaClass(f);
                jc.accept(visitor);
            } catch (ClassNotFoundException e) {
                throw new IOException(e.getMessage(), e);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        new PackageExportAnalysis().execute();
    }

    private static Predicate<Type> reportPredicate() {
        // includes:
        return t -> {
            Type basic = t;
            if (basic instanceof ArrayType) {
                basic = ((ArrayType) basic).getBasicType();
            }
            if (basic instanceof ObjectType) {
                ObjectType ot = (ObjectType) basic;
                String name = ot.getClassName();
                for (String w : whitelist) {
                    if (name.startsWith(w)) {
                        // package whitelisted, ignore
                        return false;
                    }
                }
                return true;
            }
            return false;
        };
    }

    static JavaClass getJavaClass(final String name) throws ClassNotFoundException, IOException {
        JavaClass java_class;
        if ((java_class = Repository.lookupClass(name)) == null) {
            java_class = new ClassParser(name).parse(); // May throw IOException
        }
        return java_class;
    }

    private static final class ClassVisitor extends EmptyVisitor {

        private final Predicate<Type> report;

        private String className;

        public ClassVisitor(Predicate<Type> report) {
            this.report = report;
        }

        @Override
        public void visitJavaClass(JavaClass clazz) {
            className = clazz.getClassName();
            log.debug("class {}", className);

            final Field[] fields = clazz.getFields();
            if (fields.length > 0) {
                for (final Field field : fields) {
                    field.accept(this);
                }
            }
            final Method[] methods = clazz.getMethods();
            for (int i = 0; i < methods.length; i++) {
                methods[i].accept(this);
            }
        }

        @Override
        public void visitField(Field field) {
            if (!include(field, field.getType())) {
                log.debug("{}#{}, skipped.", className, field.getName());
                return;
            }
            log.info("{}#{},{}", className, field.getName(), field.getSignature());
        }

        @Override
        public void visitMethod(Method method) {
            if (!include(method, method.getReturnType(), method.getArgumentTypes())) {
                log.debug("{}#{}, skipped.", className, method.getName());
                return;
            }
            log.info("{}#{},{}", className, method.getName(), method.getSignature());
        }

        private boolean include(FieldOrMethod f, Type t, Type... args) {
            return isExposed(f) && (report.test(t) || any(report, args));
        }

        private static boolean any(Predicate<Type> p, Type... args) {
            for (Type t : args) {
                if (p.test(t)) {
                    return true;
                }
            }
            return false;
        }

        private static boolean isExposed(AccessFlags flags) {
            return flags.isPublic() || flags.isProtected();
        }
    }
}
