//! Process-wide protections for secrets that pass through code we do not
//! control (the FIDO library, `rpassword`, `cargo-credential`, std).

use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
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
