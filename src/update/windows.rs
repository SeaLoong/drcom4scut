//! Copy the original file's owner, group and access rules before replacement.
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
        DACL_SECURITY_INFORMATION, EqualSid, GROUP_SECURITY_INFORMATION,
        GetSecurityDescriptorControl, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    },
};

use super::{UpdateError, invalid};

const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;

struct FileSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    dacl: *mut ACL,
    owner: PSID,
    group: PSID,
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
        let mut owner = ptr::null_mut();
        let mut group = ptr::null_mut();
        // SAFETY: live handle and valid output slots. The owner/group SIDs and
        // DACL remain alive in the returned descriptor. No SACL is requested.
        let error = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
                &mut owner,
                &mut group,
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
            owner,
            group,
            protected: false,
        };
        if owner.is_null() || group.is_null() {
            return Err(invalid("cannot identify executable Windows owner or group"));
        }
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
        let current = Self::read(path)?;
        let owner_changed = !sid_matches(self.owner, current.owner);
        let group_changed = !sid_matches(self.group, current.group);
        let ownership = if owner_changed {
            OWNER_SECURITY_INFORMATION
        } else {
            0
        } | if group_changed {
            GROUP_SECURITY_INFORMATION
        } else {
            0
        };
        // Do not request WRITE_OWNER when the identities already match. No
        // privilege is enabled: an ineligible owner/group fails before rename.
        let file = fs::OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC | if ownership != 0 { WRITE_OWNER } else { 0 })
            .open(path)?;
        let inheritance = if self.protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        // SAFETY: live handle and original descriptor/SIDs/ACL. Windows copies
        // the requested components before returning. No SACL is changed.
        let error = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | inheritance | ownership,
                self.owner,
                self.group,
                self.dacl,
                ptr::null(),
            )
        };
        if error != ERROR_SUCCESS {
            return Err(invalid(
                "cannot preserve executable Windows owner, group or access rules; original executable was retained",
            ));
        }
        Ok(())
    }

    fn apply(&self, path: &Path) -> Result<(), UpdateError> {
        self.write(path)?;
        let staged = Self::read(path)?;
        if staged.protected != self.protected
            || staged.rules() != self.rules()
            || !sid_matches(self.owner, staged.owner)
            || !sid_matches(self.group, staged.group)
        {
            return Err(invalid(
                "staged executable Windows owner, group or access rules differ from the original",
            ));
        }
        Ok(())
    }
}

fn sid_matches(expected: PSID, actual: PSID) -> bool {
    // DACL-only test descriptors leave the identities unspecified. Production
    // snapshots reject missing owner/group SIDs in FileSecurity::read.
    expected.is_null()
        || !actual.is_null()
            && unsafe {
                // SAFETY: both SIDs reside in live OS-provided security descriptors.
                EqualSid(expected, actual) != 0
            }
}

pub(super) fn preserve_security(original: &Path, staged: &Path) -> Result<(), UpdateError> {
    FileSecurity::read(original)?.apply(staged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    fn current_user() -> Vec<usize> {
        let mut token = ptr::null_mut();
        // SAFETY: a valid pseudo process handle and a valid output handle slot.
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
            0
        );
        // SAFETY: OpenProcessToken returned a uniquely owned real handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut length = 0;
        // SAFETY: querying the required size does not write to a null buffer.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut length,
            );
        }
        assert!(length as usize >= std::mem::size_of::<TOKEN_USER>());
        // usize storage aligns TOKEN_USER and keeps its embedded SID alive.
        let mut data = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: aligned output storage has at least the requested byte count.
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenUser,
                    data.as_mut_ptr().cast(),
                    length,
                    &mut length,
                )
            },
            0
        );
        data
    }

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
            owner: ptr::null_mut(),
            group: ptr::null_mut(),
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

    #[test]
    fn windows_update_preserves_user_owner_and_group_with_owner_rights_acl() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("core.exe");
        fs::write(&target, b"original").unwrap();
        let default = FileSecurity::read(&target).unwrap();
        let token = current_user();
        // SAFETY: GetTokenInformation initialized this aligned TOKEN_USER; its
        // SID points into token's still-live buffer.
        let user = unsafe { (*token.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        if !sid_matches(user, default.owner) {
            let file = fs::OpenOptions::new()
                .access_mode(WRITE_OWNER)
                .open(&target)
                .unwrap();
            // SAFETY: live handle and current token user SID. Assigning one's
            // own eligible SID needs no extra privilege or privilege enabling.
            assert_eq!(
                unsafe {
                    SetSecurityInfo(
                        file.as_raw_handle(),
                        SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION,
                        user,
                        ptr::null_mut(),
                        ptr::null(),
                        ptr::null(),
                    )
                },
                ERROR_SUCCESS
            );
        }
        custom_rules(&target);
        let original = FileSecurity::read(&target).unwrap();
        assert!(sid_matches(user, original.owner));
        let probe = directory.path().join("default-owner");
        fs::write(&probe, b"staged").unwrap();
        let fresh = FileSecurity::read(&probe).unwrap();
        // Elevated runners normally create Administrators-owned files. Force
        // the original to TokenUser above, exercising the differing-owner case.
        // A non-elevated runner still verifies user/group preservation below.
        assert_eq!(
            sid_matches(default.owner, user),
            sid_matches(fresh.owner, user)
        );
        if !sid_matches(default.owner, user) {
            assert!(!sid_matches(original.owner, fresh.owner));
        }
        let reached_commit = std::cell::Cell::new(false);
        assert!(
            super::super::install_with(&target, b"uncommitted", || {
                reached_commit.set(true);
                Err(std::io::Error::other("injected commit failure"))
            })
            .is_err()
        );
        assert!(
            reached_commit.get(),
            "security must be preserved before testing rollback"
        );
        let restored = FileSecurity::read(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"original");
        assert!(sid_matches(original.owner, restored.owner));
        assert!(sid_matches(original.group, restored.group));
        assert_eq!(original.rules(), restored.rules());
        super::super::install_binary(&target, b"replacement").unwrap();
        let installed = FileSecurity::read(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"replacement");
        assert!(sid_matches(original.owner, installed.owner));
        assert!(sid_matches(original.group, installed.group));
        assert_eq!(original.rules(), installed.rules());
        assert_eq!(original.protected, installed.protected);
    }
}
