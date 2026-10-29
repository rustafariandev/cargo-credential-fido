//! UTF-16 string helpers for Windows API calls.

use windows_sys::core::PCWSTR;

/// A NUL-terminated UTF-16 copy of `s`.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// The characters of a NUL-terminated UTF-16 string, without the NUL.
///
/// # Safety
///
/// `p` must be null or point to a NUL-terminated string that outlives `'a`.
pub unsafe fn wide_slice<'a>(p: PCWSTR) -> &'a [u16] {
    if p.is_null() {
        return &[];
    }
    let mut len = 0;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    unsafe { std::slice::from_raw_parts(p, len) }
}

/// # Safety
///
/// As for [`wide_slice`], for both strings.
pub unsafe fn wide_eq(a: PCWSTR, b: PCWSTR) -> bool {
    unsafe { wide_slice(a) == wide_slice(b) }
}

/// # Safety
///
/// As for [`wide_slice`].
pub unsafe fn from_wide(p: PCWSTR) -> String {
    String::from_utf16_lossy(unsafe { wide_slice(p) })
}
