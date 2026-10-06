//! Preserve Java's existing trust roots while adding the interception CA.

use std::collections::BTreeSet;
use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::AsRawFd;
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
const JAVA_IMPORT_BUDGET: Duration = Duration::from_secs(30);
const JAVA_ROOTS: &[&str] = &["/usr/lib/jvm", "/usr/java", "/opt/java", "/opt/jdk"];
const SYSTEM_STORES: &[&str] = &["/etc/ssl/certs/java/cacerts", "/etc/pki/java/cacerts"];
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A sibling file ensures publication uses a rename on the same filesystem.
struct StoreCopy(PathBuf);

/// Includes POSIX access ACLs and security labels, stored as Linux xattrs.
struct StoreAttribute {
    name: CString,
    value: Vec<u8>,
}

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
    let deadline = Instant::now() + JAVA_IMPORT_BUDGET;
    let stores = discover_stores();
    if stores.is_empty() {
        eprintln!(
            "tls: no Java trust store with keytool found; Java installed later needs manual CA import from {}",
            ca_path.display()
        );
    }
    install_into_stores(stores, ca_path, deadline);
}

fn install_into_stores(stores: Vec<(PathBuf, PathBuf)>, ca_path: &Path, deadline: Instant) {
    let count = stores.len();
    for (index, (store, keytool)) in stores.into_iter().enumerate() {
        if remaining_time(deadline).is_err() {
            eprintln!(
                "tls: Java CA import time budget exhausted; {} remaining trust stores need manual CA import from {}",
                count - index,
                ca_path.display()
            );
            break;
        }
        match import_ca(&keytool, &store, ca_path, deadline) {
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

fn discover_stores() -> Vec<(PathBuf, PathBuf)> {
    let mut homes = Vec::new();
    if let Some(home) = env::var_os("JAVA_HOME") {
        homes.push(PathBuf::from(home));
    }
    if let Some(path) = env::var_os("PATH") {
        homes.extend(homes_from_path(&path));
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

    let mut stores = stores_for_homes(homes);
    // Some distributions keep their shared cacerts outside the JDK directory.
    if let Some((_, keytool)) = stores.first().cloned() {
        for path in SYSTEM_STORES {
            if let Ok(store) = fs::canonicalize(path)
                && !stores.iter().any(|(existing, _)| *existing == store)
            {
                stores.push((store, keytool.clone()));
            }
        }
    }
    stores
}

fn homes_from_path(path: &OsStr) -> Vec<PathBuf> {
    let mut homes = Vec::new();
    // Discover Java in PATH order before any keytool-only installations. A
    // keytool in an earlier directory must not displace the selected JVM.
    for name in ["java", "keytool"] {
        for directory in env::split_paths(path).filter(|path| path.is_absolute()) {
            if let Ok(executable) = fs::canonicalize(directory.join(name))
                && let Ok(metadata) = fs::metadata(&executable)
                && metadata.is_file()
                && metadata.permissions().mode() & 0o111 != 0
                && let Some(home) = executable.parent().and_then(Path::parent)
            {
                homes.push(home.to_path_buf());
            }
        }
    }
    homes
}

fn stores_for_homes(homes: Vec<PathBuf>) -> Vec<(PathBuf, PathBuf)> {
    let mut stores = Vec::new();
    let mut seen = BTreeSet::new();
    for home in homes {
        if !home.is_absolute() {
            eprintln!(
                "tls: ignoring relative Java installation path {} (expected an absolute guest path)",
                home.display()
            );
            continue;
        }
        if let Some((store, keytool)) = installation_store(&home)
            && seen.insert(store.clone())
        {
            // Preserve discovery priority, not the canonical store's path order.
            stores.push((store, keytool));
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

fn import_ca(keytool: &Path, store: &Path, ca: &Path, deadline: Instant) -> io::Result<()> {
    remaining_time(deadline)?;
    // Never attempt to rewrite immutable Nix packages, even as root.
    if store.starts_with("/nix/store") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Nix trust store is immutable",
        ));
    }
    let mut original = fs::File::open(store)?;
    let metadata = original.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o222 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "trust store is not a writable regular file",
        ));
    }
    let parent = store
        .parent()
        .ok_or_else(|| io::Error::other("trust store has no parent"))?;
    let attributes = read_store_attributes(&original)?;
    let (copy, mut file) = StoreCopy::create(parent)?;
    io::copy(&mut original, &mut file)?;
    // Keep the staging copy private until keytool has finished writing it.
    drop(file);

    let listed = run_keytool(keytool, &copy.0, &["-list", "-alias", CA_ALIAS], deadline)?;
    if listed {
        require_keytool(keytool, &copy.0, &["-delete", "-alias", CA_ALIAS], deadline)?;
    }
    let ca = ca
        .to_str()
        .ok_or_else(|| io::Error::other("CA path is not UTF-8"))?;
    require_keytool(
        keytool,
        &copy.0,
        &["-importcert", "-noprompt", "-alias", CA_ALIAS, "-file", ca],
        deadline,
    )?;
    publish_store(&copy, store, &metadata, &attributes, deadline)
}

fn publish_store(
    copy: &StoreCopy,
    store: &Path,
    metadata: &fs::Metadata,
    attributes: &[StoreAttribute],
    deadline: Instant,
) -> io::Result<()> {
    remaining_time(deadline)?;
    std::os::unix::fs::chown(&copy.0, Some(metadata.uid()), Some(metadata.gid()))?;
    fs::set_permissions(&copy.0, metadata.permissions())?;
    let staged = fs::File::open(&copy.0)?;
    // Restore ACLs after chmod, which otherwise changes their access mask.
    restore_store_attributes(&staged, attributes)?;
    staged.sync_all()?;
    remaining_time(deadline)?;
    fs::rename(&copy.0, store)?;
    Ok(())
}

fn require_keytool(
    keytool: &Path,
    store: &Path,
    args: &[&str],
    deadline: Instant,
) -> io::Result<()> {
    if run_keytool(keytool, store, args, deadline)? {
        Ok(())
    } else {
        Err(io::Error::other(
            "keytool failed (trust store may use a non-default password or unsupported format); original store was preserved",
        ))
    }
}

fn run_keytool(keytool: &Path, store: &Path, args: &[&str], deadline: Instant) -> io::Result<bool> {
    let command_deadline = deadline.min(Instant::now() + KEYTOOL_TIMEOUT);
    remaining_time(command_deadline)?;
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
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.success()),
            Ok(None) if Instant::now() < command_deadline => {
                thread::sleep(Duration::from_millis(10))
            }
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

fn remaining_time(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Java CA import time budget exhausted; original trust store was preserved",
            )
        })
}

fn read_store_attributes(file: &fs::File) -> io::Result<Vec<StoreAttribute>> {
    let names = list_store_attributes(file)?;
    names
        .into_iter()
        .map(|name| {
            let value = read_attribute_bytes(|buffer, length| {
                // SAFETY: file and name are valid; the buffer has length writable bytes.
                unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), buffer.cast(), length) }
            })?;
            Ok(StoreAttribute { name, value })
        })
        .collect()
}

fn list_store_attributes(file: &fs::File) -> io::Result<Vec<CString>> {
    let names = match read_attribute_bytes(|buffer, length| {
        // SAFETY: file is valid and the buffer has length writable bytes.
        unsafe { libc::flistxattr(file.as_raw_fd(), buffer.cast(), length) }
    }) {
        Ok(names) => names,
        // Filesystems without xattr support cannot hold ACLs or labels either.
        Err(error) if error.raw_os_error() == Some(libc::ENOTSUP) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| CString::new(name).map_err(io::Error::other))
        .collect()
}

fn read_attribute_bytes(
    mut read: impl FnMut(*mut u8, usize) -> libc::ssize_t,
) -> io::Result<Vec<u8>> {
    // Bound retries if another process continuously changes the xattrs.
    for _ in 0..8 {
        let length = read(std::ptr::null_mut(), 0);
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        let mut bytes = vec![0; length as usize];
        let actual = read(bytes.as_mut_ptr(), bytes.len());
        if actual >= 0 {
            bytes.truncate(actual as usize);
            return Ok(bytes);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ERANGE) {
            return Err(error);
        }
    }
    Err(io::Error::other(
        "Java trust-store attributes kept changing",
    ))
}

fn restore_store_attributes(file: &fs::File, attributes: &[StoreAttribute]) -> io::Result<()> {
    let current = read_store_attributes(file)?;
    // Remove ACLs or labels inherited from the staging directory when the
    // original store did not have them, rather than adding extra access rules.
    for inherited in &current {
        if !attributes
            .iter()
            .any(|attribute| attribute.name == inherited.name)
        {
            // SAFETY: file is valid and name is NUL-terminated.
            let result = unsafe { libc::fremovexattr(file.as_raw_fd(), inherited.name.as_ptr()) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    for attribute in attributes {
        // Identical inherited labels need no relabel permission.
        if current
            .iter()
            .any(|existing| existing.name == attribute.name && existing.value == attribute.value)
        {
            continue;
        }
        // SAFETY: file/name are valid; value points to value.len() readable bytes.
        let result = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                attribute.name.as_ptr(),
                attribute.value.as_ptr().cast(),
                attribute.value.len(),
                0,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::unix::fs::symlink;
    use std::os::unix::process::CommandExt;

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
    fn selected_java_home_precedes_path_and_shared_stores_are_deduplicated() {
        let dir = TestDir::new();
        let script = "#!/bin/sh\nexit 0\n";
        let selected_tool = dir.write("z-selected/bin/keytool", script);
        fs::set_permissions(&selected_tool, fs::Permissions::from_mode(0o755)).unwrap();
        let selected_store = dir.write("z-selected/lib/security/cacerts", "selected roots");
        let other_tool = dir.write("a-other/bin/keytool", script);
        fs::set_permissions(&other_tool, fs::Permissions::from_mode(0o755)).unwrap();
        let java = dir.write("a-other/bin/java", script);
        fs::set_permissions(java, fs::Permissions::from_mode(0o755)).unwrap();
        let other_store = dir.write("a-other/lib/security/cacerts", "other roots");
        let shared_home = dir.0.join("shared-home");
        fs::create_dir_all(shared_home.join("bin")).unwrap();
        fs::create_dir_all(shared_home.join("lib/security")).unwrap();
        symlink(&other_tool, shared_home.join("bin/keytool")).unwrap();
        symlink(&selected_store, shared_home.join("lib/security/cacerts")).unwrap();
        let mut homes = vec![dir.0.join("z-selected")]; // JAVA_HOME is first.
        homes.extend(homes_from_path(
            &env::join_paths([dir.0.join("a-other/bin")]).unwrap(),
        ));
        homes.push(shared_home);
        assert_eq!(
            stores_for_homes(homes),
            vec![(selected_store, selected_tool), (other_store, other_tool)]
        );
    }

    #[test]
    fn selected_path_java_is_imported_before_slow_unrelated_jdks() {
        if isolated("tls::java::tests::selected_path_java_is_imported_before_slow_unrelated_jdks") {
            return;
        }
        let dir = TestDir::new();
        let selected_tool = dir.write("z-selected/bin/keytool", "#!/bin/sh\noperation=$1\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = -keystore ]; then shift; store=$1; fi\n  shift\ndone\n[ \"$operation\" = -list ] && exit 1\nprintf '\\nmsb CA' >> \"$store\"\n");
        fs::set_permissions(selected_tool, fs::Permissions::from_mode(0o755)).unwrap();
        let java = dir.write("z-selected/bin/java", "#!/bin/sh\nexit 0\n");
        fs::set_permissions(java, fs::Permissions::from_mode(0o755)).unwrap();
        let selected = dir.write("z-selected/lib/security/cacerts", "selected roots");
        let slow_tool = dir.write("a-slow/bin/keytool", "#!/bin/sh\nexec /bin/sleep 5\n");
        fs::set_permissions(slow_tool, fs::Permissions::from_mode(0o755)).unwrap();
        let slow = dir.write("a-slow/lib/security/cacerts", "slow roots");
        // An unrelated keytool comes first in PATH and its store sorts first.
        let path =
            env::join_paths([dir.0.join("a-slow/bin"), dir.0.join("z-selected/bin")]).unwrap();
        let stores = stores_for_homes(homes_from_path(&path));
        assert_eq!(stores.first().unwrap().0, selected);
        let ca = dir.write("ca.pem", "CA");
        install_into_stores(stores, &ca, Instant::now() + Duration::from_millis(300));
        assert_eq!(
            fs::read_to_string(selected).unwrap(),
            "selected roots\nmsb CA"
        );
        assert_eq!(fs::read_to_string(slow).unwrap(), "slow roots");
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
        assert!(import_ca(&keytool, &store, &ca, Instant::now() + KEYTOOL_TIMEOUT).is_err());
        assert_eq!(
            fs::read_to_string(&store).unwrap(),
            "existing private roots"
        );
        dir.keytool("#!/bin/sh\nexec /bin/sleep 5\n");
        let error = import_ca(
            &keytool,
            &store,
            &ca,
            Instant::now() + Duration::from_millis(30),
        )
        .unwrap_err();
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
            Instant::now() + KEYTOOL_TIMEOUT,
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
        assert!(import_ca(&keytool, &store, &ca, Instant::now() + KEYTOOL_TIMEOUT).is_err());
        assert_eq!(fs::read_to_string(&store).unwrap(), "original");
        assert!(
            import_ca(
                &keytool,
                Path::new("/nix/store/jdk/lib/security/cacerts"),
                &ca,
                Instant::now() + KEYTOOL_TIMEOUT
            )
            .is_err()
        );
        let missing = dir.0.join("missing");
        assert!(import_ca(&keytool, &missing, &ca, Instant::now() + KEYTOOL_TIMEOUT).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn imports_share_one_deadline_across_stores_and_commands() {
        if isolated("tls::java::tests::imports_share_one_deadline_across_stores_and_commands") {
            return;
        }
        let dir = TestDir::new();
        let calls = dir.0.join("calls");
        let keytool = dir.keytool(&format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{}'\nexec /bin/sleep 0.2\n",
            calls.display()
        ));
        let ca = dir.write("ca.pem", "CA");
        let first = dir.write("first-cacerts", "first roots");
        let second = dir.write("second-cacerts", "second roots");
        let deadline = Instant::now() + Duration::from_millis(300);
        let error = import_ca(&keytool, &first, &ca, deadline).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        // The second keytool call has only the remaining budget, not another 300ms.
        let recorded = fs::read_to_string(&calls).unwrap();
        assert!(
            recorded == "-list\n" || recorded == "-list\n-delete\n",
            "unexpected calls: {recorded}"
        );
        assert_eq!(fs::read_to_string(&first).unwrap(), "first roots");

        fs::remove_file(&calls).unwrap();
        let stores = [
            (first.clone(), keytool.clone()),
            (second.clone(), keytool.clone()),
        ]
        .into();
        install_into_stores(stores, &ca, Instant::now() + Duration::from_millis(100));
        assert_eq!(fs::read_to_string(&calls).unwrap(), "-list\n");
        assert_eq!(fs::read_to_string(first).unwrap(), "first roots");
        assert_eq!(fs::read_to_string(second).unwrap(), "second roots");

        fs::remove_file(&calls).unwrap();
        assert_eq!(
            import_ca(&keytool, &dir.0.join("first-cacerts"), &ca, Instant::now())
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(!calls.exists(), "an expired budget must not start keytool");
    }

    #[test]
    fn import_preserves_access_acl_and_extended_attributes() {
        if isolated("tls::java::tests::import_preserves_access_acl_and_extended_attributes") {
            return;
        }
        let dir = TestDir::new();
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        let keytool = dir.keytool("#!/bin/sh\noperation=$1\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = -keystore ]; then shift; store=$1; fi\n  shift\ndone\n[ \"$operation\" = -list ] && exit 1\nprintf '\\nmsb CA' >> \"$store\"\n");
        let store = dir.write("cacerts", "private roots");
        let ca = dir.write("ca.pem", "CA");
        let file = fs::File::open(&store).unwrap();
        // Linux POSIX ACL v2: owner rw, named user 65534 r, owning group
        // none, mask r, other none. Without the ACL, that user cannot read.
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, permissions, id) in [
            (1u16, 6u16, u32::MAX),
            (2, 4, 65534),
            (4, 0, u32::MAX),
            (16, 4, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            acl.extend(tag.to_le_bytes());
            acl.extend(permissions.to_le_bytes());
            acl.extend(id.to_le_bytes());
        }
        let attributes = [
            StoreAttribute {
                name: CString::new("system.posix_acl_access").unwrap(),
                value: acl,
            },
            StoreAttribute {
                name: CString::new("user.msb-test").unwrap(),
                value: b"original metadata".to_vec(),
            },
        ];
        restore_store_attributes(&file, &attributes).unwrap();
        let before = read_store_attributes(&file).unwrap();
        let assert_reader_access = || {
            // SAFETY: geteuid has no arguments and no preconditions.
            if unsafe { libc::geteuid() } == 0 {
                let result = Command::new("/bin/cat")
                    .arg(&store)
                    .uid(65534)
                    .gid(65534)
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
            }
        };
        assert_reader_access();
        import_ca(&keytool, &store, &ca, Instant::now() + KEYTOOL_TIMEOUT).unwrap();
        let after = read_store_attributes(&fs::File::open(&store).unwrap()).unwrap();
        for attribute in before {
            assert!(after.iter().any(
                |restored| restored.name == attribute.name && restored.value == attribute.value
            ));
        }
        assert_reader_access();
        assert_eq!(fs::read_to_string(&store).unwrap(), "private roots\nmsb CA");
    }

    #[test]
    fn restoring_attributes_removes_inherited_access_rules_and_reports_failures() {
        let dir = TestDir::new();
        let path = dir.write("staged-cacerts", "staged roots");
        let file = fs::File::open(path).unwrap();
        let inherited = StoreAttribute {
            name: CString::new("user.inherited").unwrap(),
            value: b"not on original store".to_vec(),
        };
        restore_store_attributes(&file, &[inherited]).unwrap();
        restore_store_attributes(&file, &[]).unwrap();
        assert!(read_store_attributes(&file).unwrap().is_empty());
        // An invalid namespace is rejected instead of silently losing metadata.
        let invalid = StoreAttribute {
            name: CString::new("invalid-namespace").unwrap(),
            value: Vec::new(),
        };
        let original = dir.write("cacerts", "original roots");
        let metadata = fs::metadata(&original).unwrap();
        let (copy, handle) = StoreCopy::create(&dir.0).unwrap();
        drop(handle);
        fs::write(&copy.0, "new roots").unwrap();
        assert!(
            publish_store(
                &copy,
                &original,
                &metadata,
                &[invalid],
                Instant::now() + KEYTOOL_TIMEOUT
            )
            .is_err()
        );
        assert_eq!(fs::read_to_string(original).unwrap(), "original roots");
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
                Instant::now() + KEYTOOL_TIMEOUT,
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
            require_keytool(
                &keytool,
                &store,
                &export_root,
                Instant::now() + KEYTOOL_TIMEOUT,
            )
            .unwrap();
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
                import_ca(&keytool, &store, &ca, Instant::now() + KEYTOOL_TIMEOUT).unwrap();
                let result = handshake();
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                import_ca(&keytool, &store, &ca, Instant::now() + KEYTOOL_TIMEOUT).unwrap();
                require_keytool(
                    &keytool,
                    &store,
                    &["-list", "-alias", "private-root"],
                    Instant::now() + KEYTOOL_TIMEOUT,
                )
                .unwrap();
                require_keytool(
                    &keytool,
                    &store,
                    &export_root,
                    Instant::now() + KEYTOOL_TIMEOUT,
                )
                .unwrap();
                assert_eq!(fs::read(&private_root).unwrap(), original_root);
            }
            let original = fs::read(&store).unwrap();
            fs::write(&ca, "invalid certificate").unwrap();
            assert!(import_ca(&keytool, &store, &ca, Instant::now() + KEYTOOL_TIMEOUT).is_err());
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
                Instant::now() + KEYTOOL_TIMEOUT,
            )
            .unwrap();

            let protected = dir.0.join(format!("protected-{format}"));
            fs::copy(&store, &protected).unwrap();
            require_keytool(
                &keytool,
                &protected,
                &["-storepasswd", "-new", "custom-password"],
                Instant::now() + KEYTOOL_TIMEOUT,
            )
            .unwrap();
            let original = fs::read(&protected).unwrap();
            assert!(
                import_ca(&keytool, &protected, &ca, Instant::now() + KEYTOOL_TIMEOUT).is_err()
            );
            assert_eq!(fs::read(&protected).unwrap(), original);
        }
    }
}
