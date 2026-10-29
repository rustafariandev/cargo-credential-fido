//! Process-wide protections for secrets that pass through code we do not
//! control (the FIDO library, `rpassword`, `cargo-credential`, std).

use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::MaybeUninit;
use std::path::Path;
use zeroize::Zeroize;

/// The system allocator, but every block is zeroed before it is freed.
///
/// Our own secrets are wrapped in `Zeroizing`, but dependencies copy them
/// into plain `Vec`s and `String`s (PIN protocol shared secrets, decrypted
/// hmac-secret outputs, line buffers, JSON buffers) and free them as is.
/// `realloc` is not overridden: the default implementation allocates,
/// copies and calls `dealloc`, so the old block is zeroed too.
pub struct ZeroizingAlloc;

unsafe impl GlobalAlloc for ZeroizingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // The block may be partly uninitialized, hence `MaybeUninit`.
        unsafe {
            std::slice::from_raw_parts_mut(ptr.cast::<MaybeUninit<u8>>(), layout.size()).zeroize();
            System.dealloc(ptr, layout);
        }
    }
}

/// Keep secrets out of core dumps, debuggers and swap. Best effort: each
/// step is skipped silently if the OS refuses it.
pub fn harden() {
    #[cfg(windows)]
    windows::harden();

    #[cfg(unix)]
    unsafe {
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &no_core);
    }

    // macOS does not implement mlockall, but always encrypts swap.
    #[cfg(all(unix, not(target_os = "macos")))]
    unsafe {
        // Locking future mappings makes any allocation beyond RLIMIT_MEMLOCK
        // fail (and abort the process), so only do it when that cannot
        // happen. Otherwise fall back to locking what is mapped now.
        let mut limit = MaybeUninit::<libc::rlimit>::uninit();
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, limit.as_mut_ptr()) == 0 {
            let mut limit = limit.assume_init();
            limit.rlim_cur = limit.rlim_max;
            libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit);
            let flags = if limit.rlim_cur == libc::RLIM_INFINITY {
                libc::MCL_CURRENT | libc::MCL_FUTURE
            } else {
                libc::MCL_CURRENT
            };
            libc::mlockall(flags);
        }
    }

    // Also blocks ptrace and /proc/<pid>/mem access by other processes of
    // the same (non-root) user.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }

    // Refuse debugger attachment. If a debugger is already attached, the
    // kernel terminates the process instead.
    #[cfg(target_os = "macos")]
    unsafe {
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
}

#[cfg(windows)]
mod windows {
    use crate::win::{from_wide, wide};
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION,
        SetKernelObjectSecurity, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
    };
    use windows_sys::Win32::System::ErrorReporting::{
        WER_FAULT_REPORTING_FLAG_NOHEAP, WerSetFlags,
    };
    use windows_sys::Win32::System::SystemServices::PROCESS_MITIGATION_IMAGE_LOAD_POLICY;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcessToken, PROCESS_MITIGATION_POLICY, ProcessImageLoadPolicy,
        SetProcessMitigationPolicy,
    };

    /// The right to change an object's DACL (in `Win32_Storage_FileSystem`,
    /// which we otherwise do not need).
    const WRITE_DAC: u32 = 0x0004_0000;

    /// The process DACL. SYSTEM keeps full access. The owner (this user) may
    /// only wait on, query and terminate the process (SYNCHRONIZE |
    /// PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE). The OWNER
    /// RIGHTS (`OW`) entry replaces the owner's implicit READ_CONTROL and
    /// WRITE_DAC, so the user's other processes can neither read our memory,
    /// inject a thread or attach a debugger, nor rewrite this DACL first.
    /// Handles opened before this runs, like cargo's handle on its child,
    /// keep their access.
    const PROCESS_SDDL: &str = "D:P(A;;GA;;;SY)(A;;0x101001;;;OW)";

    /// `NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images`.
    const IMAGE_LOAD_SAFE: u32 = 0b111;

    pub fn harden() {
        unsafe {
            // No crash dialog, and no heap in Windows Error Reporting dumps.
            // An administrator's LocalDumps setting still applies.
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
            WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP);
        }
        restrict_process_access();

        // No MicrosoftSignedOnly signature policy: the WebAuthn call can
        // need DLLs from other vendors (security software, input methods),
        // and refusing them fails it with an opaque HRESULT. The process
        // DACL already keeps the user's other processes from injecting one.
        let mut image_load = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default();
        image_load.Anonymous.Flags = IMAGE_LOAD_SAFE;
        set_policy(ProcessImageLoadPolicy, &image_load);
    }

    fn restrict_process_access() {
        let _ = set_dacl(unsafe { GetCurrentProcess() }, PROCESS_SDDL);
    }

    /// Open the file for writing (`GENERIC_WRITE`) and for setting its DACL,
    /// shared with no one, so no other handle can be opened on it before
    /// `restrict_file` runs.
    pub fn private_options(opts: &mut OpenOptions) {
        opts.access_mode(GENERIC_WRITE | WRITE_DAC).share_mode(0);
    }

    /// Give only SYSTEM and the current user access to `file`, replacing the
    /// permissions it inherited from its directory.
    pub fn restrict_file(file: &File) -> io::Result<()> {
        let sid = current_user_sid()?;
        set_dacl(
            file.as_raw_handle(),
            &format!("D:P(A;;FA;;;SY)(A;;FA;;;{sid})"),
        )
    }

    /// The current user's SID, as a string (`S-1-5-21-...`).
    fn current_user_sid() -> io::Result<String> {
        unsafe {
            let mut token = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            // TOKEN_USER and the SID it points to; a SID is at most 68 bytes.
            let mut buf = [0u64; 32];
            let mut len = 0;
            let ok = GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                size_of_val(&buf) as u32,
                &mut len,
            );
            let err = io::Error::last_os_error();
            CloseHandle(token);
            if ok == 0 {
                return Err(err);
            }
            let user = &*buf.as_ptr().cast::<TOKEN_USER>();
            let mut string = null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut string) == 0 {
                return Err(io::Error::last_os_error());
            }
            let sid = from_wide(string);
            LocalFree(string.cast());
            Ok(sid)
        }
    }

    fn set_dacl(handle: HANDLE, sddl: &str) -> io::Result<()> {
        let sddl = wide(sddl);
        let mut descriptor = null_mut();
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let ok = SetKernelObjectSecurity(
                handle,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            );
            let err = io::Error::last_os_error();
            LocalFree(descriptor);
            if ok == 0 {
                return Err(err);
            }
        }
        Ok(())
    }

    fn set_policy<T>(policy: PROCESS_MITIGATION_POLICY, value: &T) {
        unsafe {
            SetProcessMitigationPolicy(policy, (value as *const T).cast(), size_of::<T>());
        }
    }
}

/// Create (or truncate) `path` for writing, readable only by the current
/// user: mode 0o600 on Unix, a DACL for SYSTEM and the user on Windows.
pub fn create_private(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(windows)]
    windows::private_options(&mut opts);
    let file = opts.open(path)?;
    #[cfg(windows)]
    windows::restrict_file(&file)?;
    Ok(file)
}

/// Unbuffered handles on stdin and stdout. std's `Stdin` and `Stdout` keep
/// process-wide buffers that are never freed, so anything passing through
/// them stays in memory until overwritten.
#[cfg(unix)]
pub fn raw_stdin() -> io::Result<File> {
    use std::os::fd::AsFd;
    Ok(io::stdin().as_fd().try_clone_to_owned()?.into())
}

#[cfg(unix)]
pub fn raw_stdout() -> io::Result<File> {
    use std::os::fd::AsFd;
    Ok(io::stdout().as_fd().try_clone_to_owned()?.into())
}

#[cfg(windows)]
pub fn raw_stdin() -> io::Result<File> {
    use std::os::windows::io::AsHandle;
    Ok(io::stdin().as_handle().try_clone_to_owned()?.into())
}

#[cfg(windows)]
pub fn raw_stdout() -> io::Result<File> {
    use std::os::windows::io::AsHandle;
    Ok(io::stdout().as_handle().try_clone_to_owned()?.into())
}
