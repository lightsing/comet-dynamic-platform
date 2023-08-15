use crate::log::*;
use crate::{Error, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[cfg(windows)]
pub fn lock_open_file(path: impl AsRef<Path>) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        FILE_EXECUTE, FILE_GENERIC_READ, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ,
    };
    Ok(File::options()
        .access_mode((FILE_READ_DATA | FILE_EXECUTE | FILE_GENERIC_READ).0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_DELETE).0)
        .open(&path)
        .map_err(Error::LockFile)?)
}

#[cfg(not(windows))]
pub fn lock_open_file(path: impl AsRef<Path>) -> Result<File> {
    use rustix::fs::{flock, FlockOperation};
    let f = File::open(path.as_ref())?;
    flock(&f, FlockOperation::LockExclusive)
        .map_err(std::io::Error::from)
        .map_err(Error::LockFile)?;
    Ok(f)
}

pub fn validate_file(f: &mut File, expect_digest: [u8; 64]) -> Result<()> {
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    let mut blake = blake::Blake::new(512).unwrap();
    blake.update(buf.as_slice());
    let mut digest = [0; 64];
    blake.finalise(&mut digest);
    if digest != expect_digest {
        warn!("file has been tampered");
        return Err(Error::Tampered);
    }
    Ok(())
}
