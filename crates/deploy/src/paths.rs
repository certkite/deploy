use anyhow::{Context, Result, bail, ensure};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path},
};

pub(crate) fn uid() -> u32 {
    // SAFETY: geteuid has no arguments, pointer requirements or failure state.
    unsafe { libc::geteuid() }
}
pub(crate) fn absolute(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "path must be absolute: {}",
        path.display()
    );
    ensure!(
        path.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "non-normal path: {}",
        path.display()
    );
    let mut cursor = std::path::PathBuf::new();
    for part in path.components() {
        cursor.push(part);
        let meta = fs::symlink_metadata(&cursor)
            .with_context(|| format!("inspect {}", cursor.display()))?;
        ensure!(
            !meta.file_type().is_symlink(),
            "symlink forbidden: {}",
            cursor.display()
        );
        if cursor != path {
            ensure!(meta.is_dir(), "ancestor is not a directory");
            ensure!(
                meta.uid() == 0 || meta.uid() == uid(),
                "untrusted ancestor owner"
            );
            ensure!(
                meta.mode() & 0o022 == 0 || meta.mode() & 0o1000 != 0,
                "writable non-sticky ancestor: {}",
                cursor.display()
            );
        }
    }
    Ok(())
}
pub(crate) fn root_with(path: &Path, mode: u32, group: Option<u32>) -> Result<()> {
    absolute(path)?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir()
            && meta.uid() == uid()
            && meta.mode() & 0o777 == mode
            && group.is_none_or(|gid| meta.gid() == gid),
        "target directory has unsafe ownership or permissions"
    );
    Ok(())
}
pub(crate) fn secure_file(path: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == uid() && m.mode() & 0o777 == 0o600 && m.nlink() == 1,
        "unsafe file: {}",
        path.display()
    );
    Ok(f)
}
pub(crate) fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => {
            let mut f = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            let m = f.metadata()?;
            ensure!(
                m.is_file() && m.uid() == uid() && m.mode() & 0o777 == 0o600 && m.nlink() == 1,
                "unsafe deployment file"
            );
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut f, &mut bytes)?;
            Ok(Some(bytes))
        }
    }
}
pub(crate) fn sync(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
pub(crate) fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("missing parent")?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    sync(parent)
}
pub(crate) fn directory(path: &Path) -> Result<()> {
    directory_with(path, 0o700, None)
}

pub(crate) fn set_directory_access(path: &Path, mode: u32, group: Option<u32>) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    if let Some(gid) = group {
        chown(path, gid)?;
    }
    Ok(())
}

pub(crate) fn directory_with(path: &Path, mode: u32, group: Option<u32>) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {
            set_directory_access(path, mode, group)?;
            sync(path.parent().context("missing parent")?)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => bail!(e),
    }
    root_with(path, mode, group)
}

pub(crate) fn read_certificate(
    path: &Path,
    mode: u32,
    group: Option<u32>,
) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => {
            let mut f = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            let m = f.metadata()?;
            ensure!(
                m.is_file()
                    && m.uid() == uid()
                    && m.mode() & 0o777 == mode
                    && group.is_none_or(|gid| m.gid() == gid)
                    && m.nlink() == 1,
                "unsafe certificate file"
            );
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut f, &mut bytes)?;
            Ok(Some(bytes))
        }
    }
}

pub(crate) fn atomic_certificate(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    group: Option<u32>,
) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("missing parent")?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    if let Some(gid) = group {
        chown(temp.path(), gid)?;
    }
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    sync(parent)
}

fn chown(path: &Path, gid: u32) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: path is a live NUL-terminated string; uid -1 preserves ownership.
    let result = unsafe { libc::chown(path.as_ptr(), u32::MAX, gid) };
    ensure!(result == 0, "cannot set certificate service group");
    Ok(())
}
