use std::{fs, io, path::Path};

pub(crate) fn remove_verified<E: From<io::Error>>(
    path: &Path,
    limit: u64,
    verify: impl FnOnce(&str) -> Result<(), E>,
) -> Result<bool, E> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
        };
        let Some(mut file) = crate::config::open_private_file(path, limit, true)? else {
            return Ok(false);
        };
        verify(&crate::config::read_private_handle(&mut file, limit)?)?;
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of_val(&disposition) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(true)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let metadata = fs::symlink_metadata(parent)?;
        let uid = unsafe { libc::geteuid() };
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.mode() & 0o022 != 0
            || (metadata.uid() != uid && metadata.uid() != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "credential directory is not trusted",
            )
            .into());
        }
        let quarantine = parent.join(format!(
            ".rop-delete-{}",
            hex::encode(crate::client::random_id())
        ));
        fs::DirBuilder::new().mode(0o700).create(&quarantine)?;
        let captured = quarantine.join("credential");
        if let Err(error) = fs::rename(path, &captured) {
            fs::remove_dir(&quarantine)?;
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(error.into())
            };
        }
        // Inspect only the captured entry. Its private directory prevents a path swap during validation/deletion.
        let result = (|| {
            let text = crate::config::read_private_text(&captured, limit)?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "captured credential disappeared")
            })?;
            verify(&text)?;
            fs::remove_file(&captured)?;
            Ok::<(), E>(())
        })();
        if let Err(error) = result {
            // hard_link never overwrites a concurrently created destination, including a symlink.
            if let Err(restore) = fs::hard_link(&captured, path) {
                return Err(io::Error::other(format!("credential removal aborted; restore failed: {restore}; original retained at {}", captured.display())).into());
            }
            fs::remove_file(&captured)?;
            fs::remove_dir(&quarantine)?;
            return Err(error);
        }
        fs::remove_dir(&quarantine)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(true)
    }
}

#[cfg(windows)]
pub(crate) fn validate_windows(file: &fs::File) -> io::Result<()> {
    use std::{
        ffi::c_void,
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetTokenInformation, IsWellKnownSid,
            OWNER_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER, TokenUser,
            WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid, WinLocalSystemSid,
        },
        Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    fn denied(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, message)
    }
    fn trusted_system(sid: *mut c_void) -> bool {
        unsafe {
            IsWellKnownSid(sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
        }
    }
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.nNumberOfLinks != 1 {
        return Err(denied("private file must not have hard links"));
    }

    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    // TOKEN_USER plus SECURITY_MAX_SID_SIZE, stored in pointer-aligned memory.
    let mut user = [0usize; 32];
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            user.as_mut_ptr().cast(),
            std::mem::size_of_val(&user) as u32,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let current_sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut owner = ptr::null_mut();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let result = (|| {
        if owner.is_null() || acl.is_null() {
            return Err(denied(
                "private file requires an owner and a restrictive DACL",
            ));
        }
        if unsafe { EqualSid(owner, current_sid) } == 0 && !trusted_system(owner) {
            return Err(denied(
                "private file owner must be the current user, SYSTEM or Administrators",
            ));
        }
        for index in 0..unsafe { (*acl).AceCount } {
            let mut ace = ptr::null_mut();
            if unsafe { GetAce(acl, u32::from(index), &mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            if header.AceFlags & 0x08 != 0 || header.AceType == 1 {
                continue;
            }
            if header.AceType != 0
                || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            {
                return Err(denied(
                    "private file contains an unsupported permission entry",
                ));
            }
            let sid =
                unsafe { ptr::addr_of_mut!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart).cast() };
            if unsafe { EqualSid(sid, owner) } == 0
                && unsafe { EqualSid(sid, current_sid) } == 0
                && !trusted_system(sid)
                && unsafe { IsWellKnownSid(sid, WinCreatorOwnerRightsSid) } == 0
            {
                return Err(denied(
                    "private file grants access to another principal; restrict its ACL before loading",
                ));
            }
        }
        Ok(())
    })();
    if !unsafe { LocalFree(descriptor) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_is_bound_to_the_verified_entry() {
        let directory = crate::test_support::TestDirectory::new();
        let path = directory.0.join("credential.toml");
        crate::config::write_private_toml(&path, "expected").unwrap();
        let removed = remove_verified::<io::Error>(&path, 100, |text| {
            assert_eq!(text, "expected");
            #[cfg(windows)]
            {
                assert!(fs::rename(&path, directory.0.join("moved")).is_err());
            }
            #[cfg(unix)]
            crate::config::write_private_toml(&path, "replacement").unwrap();
            Ok(())
        })
        .unwrap();
        assert!(removed);
        #[cfg(windows)]
        assert!(!path.exists());
        #[cfg(unix)]
        assert_eq!(
            crate::config::read_private_text(&path, 100)
                .unwrap()
                .unwrap(),
            "replacement"
        );
    }

    #[test]
    fn rejected_deletion_preserves_original() {
        let directory = crate::test_support::TestDirectory::new();
        let path = directory.0.join("credential.toml");
        crate::config::write_private_toml(&path, "unrelated").unwrap();
        assert!(
            remove_verified::<io::Error>(&path, 100, |_| Err(io::Error::other(
                "identity mismatch"
            )))
            .is_err()
        );
        assert_eq!(
            crate::config::read_private_text(&path, 100)
                .unwrap()
                .unwrap(),
            "unrelated"
        );
    }

    #[cfg(unix)]
    #[test]
    fn failed_restore_never_overwrites_a_new_directory_entry() {
        let directory = crate::test_support::TestDirectory::new();
        let path = directory.0.join("credential.toml");
        crate::config::write_private_toml(&path, "original").unwrap();
        let error = remove_verified::<io::Error>(&path, 100, |_| {
            crate::config::write_private_toml(&path, "replacement").unwrap();
            Err(io::Error::other("identity mismatch"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("original retained at"));
        assert_eq!(
            crate::config::read_private_text(&path, 100)
                .unwrap()
                .unwrap(),
            "replacement"
        );
        let captured = fs::read_dir(&directory.0)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.is_dir())
            .unwrap()
            .join("credential");
        assert_eq!(
            crate::config::read_private_text(&captured, 100)
                .unwrap()
                .unwrap(),
            "original"
        );
    }

    #[cfg(windows)]
    #[test]
    fn private_read_rejects_world_readable_dacl() {
        use std::{os::windows::ffi::OsStrExt, ptr};
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::{
                Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
                DACL_SECURITY_INFORMATION, SetFileSecurityW,
            },
        };
        let directory = crate::test_support::TestDirectory::new();
        let path = directory.0.join("credential.toml");
        crate::config::write_private_toml(&path, "private").unwrap();
        let text: Vec<u16> = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FR;;;WD)\0"
            .encode_utf16()
            .collect();
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut descriptor = ptr::null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            },
            0
        );
        let set = unsafe { SetFileSecurityW(wide.as_ptr(), DACL_SECURITY_INFORMATION, descriptor) };
        assert!(unsafe { LocalFree(descriptor) }.is_null());
        assert_ne!(set, 0);
        assert_eq!(
            crate::config::read_private_text(&path, 100)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
