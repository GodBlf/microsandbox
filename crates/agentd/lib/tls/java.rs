//! Preserve Java's existing trust roots while adding the interception CA.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::{env, fs, thread};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CA_ALIAS: &str = "microsandbox-intercept-ca";
const STORE_PASSWORD: &str = "changeit";
const KEYTOOL_TIMEOUT: Duration = Duration::from_secs(10);
const JAVA_ROOTS: &[&str] = &["/usr/lib/jvm", "/usr/java", "/opt/java", "/opt/jdk"];
const SYSTEM_STORES: &[&str] = &["/etc/ssl/certs/java/cacerts", "/etc/pki/java/cacerts"];
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A sibling file ensures publication uses a rename on the same filesystem.
struct StoreCopy(PathBuf);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StoreCopy {
    fn create(parent: &Path) -> io::Result<(Self, fs::File)> {
        for _ in 0..32 {
            let path = parent.join(format!(
                ".msb-java-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => return Ok((Self(path), file)),
                // A previous interrupted boot can leave a staging file behind.
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate Java trust-store staging file",
        ))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for StoreCopy {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn install_ca_cert(ca_path: &Path) {
    let stores = discover_stores();
    if stores.is_empty() {
        eprintln!(
            "tls: no Java trust store with keytool found; Java installed later needs manual CA import from {}",
            ca_path.display()
        );
    }
    for (store, keytool) in stores {
        match import_ca(&keytool, &store, ca_path, KEYTOOL_TIMEOUT) {
            Ok(()) => eprintln!(
                "tls: installed interception CA into Java trust store {}",
                store.display()
            ),
            Err(error) => eprintln!(
                "tls: could not update Java trust store {}: {error}; import {} manually for this JVM",
                store.display(),
                ca_path.display()
            ),
        }
    }
}

fn discover_stores() -> BTreeMap<PathBuf, PathBuf> {
    let mut homes = Vec::new();
    if let Some(home) = env::var_os("JAVA_HOME") {
        homes.push(PathBuf::from(home));
    }
    // Resolve executable symlinks to discover the selected JDK, including Nix.
    if let Some(path) = env::var_os("PATH") {
        for directory in env::split_paths(&path).filter(|path| path.is_absolute()) {
            for name in ["java", "keytool"] {
                if let Ok(executable) = fs::canonicalize(directory.join(name))
                    && let Some(home) = executable.parent().and_then(Path::parent)
                {
                    homes.push(home.to_path_buf());
                }
            }
        }
    }
    for root in JAVA_ROOTS {
        homes.push(PathBuf::from(root));
        add_children(Path::new(root), &mut homes);
    }
    let sdkman = env::var_os("SDKMAN_CANDIDATES_DIR")
        .map(PathBuf::from)
        .or_else(|| env::var_os("SDKMAN_DIR").map(|path| PathBuf::from(path).join("candidates")))
        .or_else(|| env::var_os("HOME").map(|path| PathBuf::from(path).join(".sdkman/candidates")));
    if let Some(root) = sdkman {
        add_children(&root.join("java"), &mut homes);
    }

    let mut stores = BTreeMap::new();
    for home in homes {
        if !home.is_absolute() {
            eprintln!(
                "tls: ignoring relative Java installation path {} (expected an absolute guest path)",
                home.display()
            );
            continue;
        }
        if let Some((store, keytool)) = installation_store(&home) {
            stores.entry(store).or_insert(keytool);
        }
    }
    // Some distributions keep their shared cacerts outside the JDK directory.
    if let Some(keytool) = stores.values().next().cloned() {
        for path in SYSTEM_STORES {
            if let Ok(store) = fs::canonicalize(path) {
                stores.entry(store).or_insert_with(|| keytool.clone());
            }
        }
    }
    stores
}

fn add_children(root: &Path, homes: &mut Vec<PathBuf>) {
    if !root.is_absolute() {
        eprintln!(
            "tls: ignoring relative Java installation directory {}",
            root.display()
        );
        return;
    }
    if let Ok(entries) = fs::read_dir(root) {
        homes.extend(entries.flatten().map(|entry| entry.path()));
    }
}

fn installation_store(home: &Path) -> Option<(PathBuf, PathBuf)> {
    let keytool = fs::canonicalize(home.join("bin/keytool")).ok()?;
    if fs::metadata(&keytool).ok()?.permissions().mode() & 0o111 == 0 {
        return None;
    }
    for security in ["lib/security", "jre/lib/security"] {
        // JSSE prefers jssecacerts over cacerts when both exist.
        for name in ["jssecacerts", "cacerts"] {
            let store = home.join(security).join(name);
            if store.exists() {
                return fs::canonicalize(store).ok().map(|store| (store, keytool));
            }
        }
    }
    None
}

fn import_ca(keytool: &Path, store: &Path, ca: &Path, timeout: Duration) -> io::Result<()> {
    // Never attempt to rewrite immutable Nix packages, even as root.
    if store.starts_with("/nix/store") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Nix trust store is immutable",
        ));
    }
    let metadata = fs::metadata(store)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o222 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "trust store is not a writable regular file",
        ));
    }
    let parent = store
        .parent()
        .ok_or_else(|| io::Error::other("trust store has no parent"))?;
    let (copy, mut file) = StoreCopy::create(parent)?;
    file.write_all(&fs::read(store)?)?;
    // Preserve guest ownership and mode; do not change the original symlink.
    std::os::unix::fs::chown(&copy.0, Some(metadata.uid()), Some(metadata.gid()))?;
    fs::set_permissions(&copy.0, metadata.permissions())?;
    drop(file);

    let listed = run_keytool(keytool, &copy.0, &["-list", "-alias", CA_ALIAS], timeout)?;
    if listed {
        require_keytool(keytool, &copy.0, &["-delete", "-alias", CA_ALIAS], timeout)?;
    }
    let ca = ca
        .to_str()
        .ok_or_else(|| io::Error::other("CA path is not UTF-8"))?;
    require_keytool(
        keytool,
        &copy.0,
        &["-importcert", "-noprompt", "-alias", CA_ALIAS, "-file", ca],
        timeout,
    )?;
    std::os::unix::fs::chown(&copy.0, Some(metadata.uid()), Some(metadata.gid()))?;
    fs::set_permissions(&copy.0, metadata.permissions())?;
    fs::File::open(&copy.0)?.sync_all()?;
    fs::rename(&copy.0, store)?;
    Ok(())
}

fn require_keytool(
    keytool: &Path,
    store: &Path,
    args: &[&str],
    timeout: Duration,
) -> io::Result<()> {
    if run_keytool(keytool, store, args, timeout)? {
        Ok(())
    } else {
        Err(io::Error::other(
            "keytool failed (trust store may use a non-default password or unsupported format); original store was preserved",
        ))
    }
}

fn run_keytool(keytool: &Path, store: &Path, args: &[&str], timeout: Duration) -> io::Result<bool> {
    let mut child = Command::new(keytool)
        .args(args)
        .arg("-keystore")
        .arg(store)
        .args(["-storepass", STORE_PASSWORD])
        // User JVM flags apply to workloads, not this maintenance helper.
        .env_remove("JAVA_TOOL_OPTIONS")
        .env_remove("JDK_JAVA_OPTIONS")
        .env_remove("_JAVA_OPTIONS")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.success()),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return match result {
                    Err(error) => Err(error),
                    _ => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "keytool timed out; original trust store was preserved",
                    )),
                };
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::unix::fs::symlink;

    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = env::temp_dir().join(format!(
                "msb-java-test-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, contents).unwrap();
            path
        }

        fn keytool(&self, script: &str) -> PathBuf {
            let path = self.write("bin/keytool", script);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    // The agent process manager in other tests can reap unrelated children.
    // Match the session tests by running command-based scenarios in isolation.
    fn isolated(test: &str) -> bool {
        const HELPER_ENV: &str = "MSB_JAVA_ISOLATED_TEST";
        if env::var(HELPER_ENV).ok().as_deref() == Some(test) {
            return false;
        }
        let mut child = Command::new(env::current_exe().unwrap())
            .args(["--exact", test, "--include-ignored", "--nocapture"])
            .env(HELPER_ENV, test)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        match child.wait() {
            Ok(status) => assert!(status.success(), "{output}"),
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {}
            Err(error) => panic!("wait for isolated Java test: {error}"),
        }
        assert!(
            output.contains("test result: ok. 1 passed; 0 failed"),
            "{output}"
        );
        true
    }

    #[test]
    fn discovery_follows_symlinks_and_prefers_jssecacerts() {
        let dir = TestDir::new();
        let tool = dir.keytool("#!/bin/sh\nexit 0\n");
        dir.write("lib/security/cacerts", "original roots");
        let shared = dir.write("shared-store", "custom roots");
        symlink(&shared, dir.0.join("lib/security/jssecacerts")).unwrap();
        let home = dir.0.join("jdk-link");
        symlink(&dir.0, &home).unwrap();
        assert_eq!(installation_store(&home), Some((shared, tool)));
    }

    #[test]
    fn discovery_requires_an_existing_store_and_executable_keytool() {
        let dir = TestDir::new();
        assert_eq!(installation_store(&dir.0), None);
        dir.keytool("#!/bin/sh\nexit 0\n");
        assert_eq!(installation_store(&dir.0), None);
        dir.write("jre/lib/security/cacerts", "Java 8 roots");
        assert!(installation_store(&dir.0).is_some());
        fs::set_permissions(dir.0.join("bin/keytool"), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(installation_store(&dir.0), None);
    }

    #[test]
    fn failed_import_and_timeout_leave_original_store_unchanged() {
        if isolated("tls::java::tests::failed_import_and_timeout_leave_original_store_unchanged") {
            return;
        }
        let dir = TestDir::new();
        let store = dir.write("cacerts", "existing private roots");
        let ca = dir.write("ca.pem", "CA");
        let keytool = dir.keytool("#!/bin/sh\nexit 1\n");
        assert!(import_ca(&keytool, &store, &ca, KEYTOOL_TIMEOUT).is_err());
        assert_eq!(
            fs::read_to_string(&store).unwrap(),
            "existing private roots"
        );
        dir.keytool("#!/bin/sh\nexec /bin/sleep 5\n");
        let error = import_ca(&keytool, &store, &ca, Duration::from_millis(30)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            fs::read_to_string(&store).unwrap(),
            "existing private roots"
        );
        assert!(!fs::read_dir(&dir.0).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".msb-java-")
        }));
    }

    #[test]
    fn import_preserves_store_permissions_and_symlink() {
        if isolated("tls::java::tests::import_preserves_store_permissions_and_symlink") {
            return;
        }
        let dir = TestDir::new();
        let keytool = dir.keytool("#!/bin/sh\noperation=$1\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = -keystore ]; then shift; store=$1; fi\n  shift\ndone\n[ \"$operation\" = -list ] && exit 1\nprintf '\\nmsb CA' >> \"$store\"\n");
        let store = dir.write("actual cacerts", "private roots");
        fs::set_permissions(&store, fs::Permissions::from_mode(0o640)).unwrap();
        let link = dir.0.join("cacerts");
        symlink(&store, &link).unwrap();
        let ca = dir.write("ca with spaces.pem", "CA");
        let stale = dir.write(
            &format!(
                ".msb-java-{}-{}",
                std::process::id(),
                NEXT_TEMP.load(Ordering::Relaxed)
            ),
            "interrupted boot copy",
        );
        import_ca(
            &keytool,
            &fs::canonicalize(&link).unwrap(),
            &ca,
            KEYTOOL_TIMEOUT,
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&link).unwrap(), "private roots\nmsb CA");
        assert_eq!(fs::read_link(link).unwrap(), store);
        assert_eq!(fs::read_to_string(stale).unwrap(), "interrupted boot copy");
        assert_eq!(
            fs::metadata(&store).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn readonly_nix_and_missing_stores_are_not_created_or_replaced() {
        let dir = TestDir::new();
        let keytool = dir.keytool("#!/bin/sh\nexit 0\n");
        let ca = dir.write("ca.pem", "CA");
        let store = dir.write("cacerts", "original");
        fs::set_permissions(&store, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(import_ca(&keytool, &store, &ca, KEYTOOL_TIMEOUT).is_err());
        assert_eq!(fs::read_to_string(&store).unwrap(), "original");
        assert!(
            import_ca(
                &keytool,
                Path::new("/nix/store/jdk/lib/security/cacerts"),
                &ca,
                KEYTOOL_TIMEOUT
            )
            .is_err()
        );
        let missing = dir.0.join("missing");
        assert!(import_ca(&keytool, &missing, &ca, KEYTOOL_TIMEOUT).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn helper_preserves_workload_options_and_uses_absolute_paths_from_another_cwd() {
        if isolated(
            "tls::java::tests::helper_preserves_workload_options_and_uses_absolute_paths_from_another_cwd",
        ) {
            return;
        }
        const CHILD_ROOT: &str = "MSB_JAVA_TEST_CHILD_ROOT";
        if let Some(root) = env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(root);
            let before =
                ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"].map(env::var_os);
            import_ca(
                &root.join("bin/keytool"),
                &root.join("cacerts"),
                &root.join("ca.pem"),
                KEYTOOL_TIMEOUT,
            )
            .unwrap();
            let after = ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"].map(env::var_os);
            assert_eq!(before, after);
            return;
        }
        let dir = TestDir::new();
        dir.write("cacerts", "original roots");
        dir.write("ca.pem", "CA");
        dir.keytool("#!/bin/sh\n[ -z \"${JAVA_TOOL_OPTIONS+x}${JDK_JAVA_OPTIONS+x}${_JAVA_OPTIONS+x}\" ] || exit 7\noperation=$1\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = -keystore ]; then shift; store=$1; fi\n  shift\ndone\n[ \"$operation\" = -list ] && exit 1\nprintf '\\nmsb CA' >> \"$store\"\n");
        let other_cwd = dir.0.join("other-directory");
        fs::create_dir(&other_cwd).unwrap();
        let output = Command::new(env::current_exe().unwrap())
            .args(["--exact", "tls::java::tests::helper_preserves_workload_options_and_uses_absolute_paths_from_another_cwd"])
            .env(CHILD_ROOT, &dir.0)
            .env("JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.trustStore=/custom/store -Xmx256m")
            .env("JDK_JAVA_OPTIONS", "-Dcustom=value")
            .env("_JAVA_OPTIONS", "-Dother=value")
            .current_dir(other_cwd)
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(dir.0.join("cacerts")).unwrap(),
            "original roots\nmsb CA"
        );
    }

    /// Run with MSB_TEST_JAVA_HOME pointing to each JDK being qualified.
    #[test]
    #[ignore = "requires a JDK; run with MSB_TEST_JAVA_HOME=/absolute/jdk/path"]
    fn real_jvm_handshake_preserves_roots_and_handles_restart_and_rotation() {
        if isolated(
            "tls::java::tests::real_jvm_handshake_preserves_roots_and_handles_restart_and_rotation",
        ) {
            return;
        }
        let home =
            PathBuf::from(env::var_os("MSB_TEST_JAVA_HOME").expect("set MSB_TEST_JAVA_HOME"));
        assert!(home.is_absolute());
        let keytool = home.join("bin/keytool");
        let producer_home = env::var_os("MSB_TEST_JAVA_PRODUCER_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.clone());
        assert!(producer_home.is_absolute());
        let producer_keytool = producer_home.join("bin/keytool");
        let dir = TestDir::new();
        let identity = dir.0.join("identity.p12");
        let ca = dir.0.join("ca.pem");
        let probe = dir.write("TlsProbe.java", r#"
import java.io.*;
import java.security.*;
import javax.net.ssl.*;
public class TlsProbe {
    public static void main(String[] args) throws Exception {
        if (!"preserved".equals(System.getProperty("msb.test.option"))) throw new Exception("lost JVM option");
        var keys = KeyStore.getInstance("PKCS12");
        try (var input = new FileInputStream(args[0])) { keys.load(input, "changeit".toCharArray()); }
        var managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(keys, "changeit".toCharArray());
        var context = SSLContext.getInstance("TLS");
        context.init(managers.getKeyManagers(), null, null);
        try (var server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            var thread = new Thread(() -> {
                try (var socket = (SSLSocket) server.accept()) { socket.startHandshake(); }
                catch (Exception ignored) {}
            });
            thread.setDaemon(true);
            thread.start();
            try (var socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket("localhost", server.getLocalPort())) {
                socket.setSoTimeout(5000);
                var parameters = socket.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                socket.setSSLParameters(parameters);
                socket.startHandshake();
            }
            thread.join(5000);
        }
    }
}
"#);
        for format in ["JKS", "PKCS12"] {
            let store = dir.0.join(format!("roots-{format}"));
            let output = Command::new(&producer_keytool)
                .args([
                    "-genkeypair",
                    "-alias",
                    "private-root",
                    "-dname",
                    "CN=Private Root",
                    "-keyalg",
                    "RSA",
                    "-validity",
                    "2",
                    "-storetype",
                    format,
                    "-storepass",
                    STORE_PASSWORD,
                    "-keypass",
                    STORE_PASSWORD,
                ])
                .arg("-keystore")
                .arg(&store)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let private_root = dir.0.join(format!("private-root-{format}.der"));
            let export_root = [
                "-exportcert",
                "-alias",
                "private-root",
                "-file",
                private_root.to_str().unwrap(),
            ];
            require_keytool(&keytool, &store, &export_root, KEYTOOL_TIMEOUT).unwrap();
            let original_root = fs::read(&private_root).unwrap();
            for rotation in 0..2 {
                if identity.exists() {
                    fs::remove_file(&identity).unwrap();
                }
                let output = Command::new(&producer_keytool)
                    .args([
                        "-genkeypair",
                        "-alias",
                        "server",
                        "-dname",
                        "CN=localhost",
                        "-ext",
                        "SAN=dns:localhost",
                        "-ext",
                        "BC=ca:true",
                        "-keyalg",
                        "RSA",
                        "-validity",
                        "2",
                        "-storetype",
                        "PKCS12",
                        "-storepass",
                        STORE_PASSWORD,
                        "-keypass",
                        STORE_PASSWORD,
                    ])
                    .arg("-keystore")
                    .arg(&identity)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let output = Command::new(&keytool)
                    .args([
                        "-exportcert",
                        "-rfc",
                        "-alias",
                        "server",
                        "-storepass",
                        STORE_PASSWORD,
                    ])
                    .arg("-keystore")
                    .arg(&identity)
                    .arg("-file")
                    .arg(&ca)
                    .output()
                    .unwrap();
                assert!(output.status.success());
                let handshake = || {
                    Command::new(home.join("bin/java"))
                        .env("JAVA_TOOL_OPTIONS", "-Dmsb.test.option=preserved")
                        .arg(format!("-Djavax.net.ssl.trustStore={}", store.display()))
                        .arg(format!("-Djavax.net.ssl.trustStoreType={format}"))
                        .arg("-Djavax.net.ssl.trustStorePassword=changeit")
                        .arg(&probe)
                        .arg(&identity)
                        .output()
                        .unwrap()
                };
                assert!(
                    !handshake().status.success(),
                    "untrusted CA accepted before import, rotation={rotation}"
                );
                import_ca(&keytool, &store, &ca, KEYTOOL_TIMEOUT).unwrap();
                let result = handshake();
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                import_ca(&keytool, &store, &ca, KEYTOOL_TIMEOUT).unwrap();
                require_keytool(
                    &keytool,
                    &store,
                    &["-list", "-alias", "private-root"],
                    KEYTOOL_TIMEOUT,
                )
                .unwrap();
                require_keytool(&keytool, &store, &export_root, KEYTOOL_TIMEOUT).unwrap();
                assert_eq!(fs::read(&private_root).unwrap(), original_root);
            }
            let original = fs::read(&store).unwrap();
            fs::write(&ca, "invalid certificate").unwrap();
            assert!(import_ca(&keytool, &store, &ca, KEYTOOL_TIMEOUT).is_err());
            assert_eq!(fs::read(&store).unwrap(), original);

            require_keytool(
                &keytool,
                &identity,
                &[
                    "-exportcert",
                    "-rfc",
                    "-alias",
                    "server",
                    "-file",
                    ca.to_str().unwrap(),
                ],
                KEYTOOL_TIMEOUT,
            )
            .unwrap();

            let protected = dir.0.join(format!("protected-{format}"));
            fs::copy(&store, &protected).unwrap();
            require_keytool(
                &keytool,
                &protected,
                &["-storepasswd", "-new", "custom-password"],
                KEYTOOL_TIMEOUT,
            )
            .unwrap();
            let original = fs::read(&protected).unwrap();
            assert!(import_ca(&keytool, &protected, &ca, KEYTOOL_TIMEOUT).is_err());
            assert_eq!(fs::read(&protected).unwrap(), original);
        }
    }
}
