//! Copy the original file's access rules before making a staged image live.
use std::{
    fs,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    ptr,
};

use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, LocalFree},
    Security::{
        ACL,
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo},
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    },
};

use super::{UpdateError, invalid};

const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;

struct FileSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    dacl: *mut ACL,
    protected: bool,
}

impl Drop for FileSecurity {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
        unsafe {
            LocalFree(self.descriptor);
        }
    }
}

impl FileSecurity {
    fn read(path: &Path) -> Result<Self, UpdateError> {
        let file = fs::OpenOptions::new()
            .access_mode(READ_CONTROL)
            .open(path)?;
        let mut descriptor = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        // SAFETY: live file handle and valid output slots; other components are
        // deliberately not requested. The allocation remains alive in Self.
        let error = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if error != ERROR_SUCCESS {
            return Err(invalid(
                "cannot read executable Windows access rules; original executable was retained",
            ));
        }
        let mut security = Self {
            descriptor,
            dacl,
            protected: false,
        };
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: the descriptor returned by Windows is live and valid.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(invalid("cannot inspect executable Windows access rules"));
        }
        security.protected = control & SE_DACL_PROTECTED != 0;
        Ok(security)
    }

    fn rules(&self) -> Vec<u8> {
        if self.dacl.is_null() {
            return Vec::new();
        }
        // SAFETY: the OS validated the ACL, which is within our live security
        // descriptor; AclSize includes the ACL header and all access entries.
        unsafe {
            std::slice::from_raw_parts(self.dacl.cast(), usize::from((*self.dacl).AclSize)).to_vec()
        }
    }

    fn write(&self, path: &Path) -> Result<(), UpdateError> {
        let file = fs::OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC)
            .open(path)?;
        let inheritance = if self.protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        // SAFETY: live destination handle and original descriptor/ACL. Windows
        // copies the ACL before returning; ownership/SACL are not changed.
        let error = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | inheritance,
                ptr::null_mut(),
                ptr::null_mut(),
                self.dacl,
                ptr::null(),
            )
        };
        if error != ERROR_SUCCESS {
            return Err(invalid(
                "cannot preserve executable Windows access rules; original executable was retained",
            ));
        }
        Ok(())
    }

    fn apply(&self, path: &Path) -> Result<(), UpdateError> {
        self.write(path)?;
        let staged = Self::read(path)?;
        if staged.protected != self.protected || staged.rules() != self.rules() {
            return Err(invalid(
                "staged executable Windows access rules differ from the original",
            ));
        }
        Ok(())
    }
}

pub(super) fn preserve_dacl(original: &Path, staged: &Path) -> Result<(), UpdateError> {
    FileSecurity::read(original)?.apply(staged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;

    fn descriptor(sddl: &str) -> FileSecurity {
        let sddl: Vec<_> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = ptr::null_mut();
        // SAFETY: valid NUL-terminated SDDL and output descriptor pointer.
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            },
            0
        );
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        // SAFETY: live descriptor and valid output slots.
        assert_ne!(
            unsafe {
                windows_sys::Win32::Security::GetSecurityDescriptorDacl(
                    descriptor,
                    &mut present,
                    &mut dacl,
                    &mut defaulted,
                )
            },
            0
        );
        FileSecurity {
            descriptor,
            dacl,
            protected: true,
        }
    }

    fn custom_rules(path: &Path) {
        // Use file-specific FR, as on an existing file. Windows expands generic
        // GR during SetSecurityInfo, so raw SDDL with GR is not a file snapshot.
        descriptor("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FR;;;WD)")
            .apply(path)
            .unwrap();
    }

    #[test]
    fn generic_file_rights_are_mapped_by_windows() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("generic.exe");
        fs::write(&target, b"original").unwrap();
        let generic = descriptor("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;GR;;;WD)");
        let file_specific = descriptor("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FR;;;WD)");
        generic.write(&target).unwrap();
        let actual = FileSecurity::read(&target).unwrap();
        assert_ne!(actual.rules(), generic.rules());
        assert_eq!(actual.rules(), file_specific.rules());
        assert!(actual.protected);
        // Production copying starts from the OS snapshot and still requires
        // an exact ACL/protection match, rather than accepting normalization.
        actual.apply(&target).unwrap();
    }

    #[test]
    fn windows_update_preserves_custom_dacl_and_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("core.exe");
        fs::write(&target, b"original").unwrap();
        custom_rules(&target);
        let original = FileSecurity::read(&target).unwrap();
        assert!(
            super::super::install_with(&target, b"uncommitted", || Err(std::io::Error::other(
                "injected commit failure"
            )))
            .is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), b"original");
        assert_eq!(
            FileSecurity::read(&target).unwrap().rules(),
            original.rules()
        );
        super::super::install_binary(&target, b"replacement").unwrap();
        let updated = FileSecurity::read(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"replacement");
        assert_eq!(updated.rules(), original.rules());
        assert_eq!(updated.protected, original.protected);
    }
}
