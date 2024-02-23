use super::*;
use libc::*;

cfg_if! {
    if #[cfg(ossl110)] {
        type CRYPTO_EX_new_ret = ();
        type CRYPTO_EX_dup_from = *const CRYPTO_EX_DATA;
    } else {
        type CRYPTO_EX_new_ret = c_int;
        type CRYPTO_EX_dup_from = *mut CRYPTO_EX_DATA;
    }
}

cfg_if! {
    if #[cfg(ossl300)] {
        type CRYPTO_EX_dup_from_d = *mut *mut c_void;
    } else {
        type CRYPTO_EX_dup_from_d = *mut c_void;
    }
}

pub type CRYPTO_EX_new = Option<
    unsafe extern "C" fn(
        parent: *mut c_void,
        ptr: *mut c_void,
        ad: *mut CRYPTO_EX_DATA,
        idx: c_int,
        argl: c_long,
        argp: *mut c_void,
    ) -> CRYPTO_EX_new_ret,
>;
pub type CRYPTO_EX_dup = Option<
    unsafe extern "C" fn(
        to: *mut CRYPTO_EX_DATA,
        from: CRYPTO_EX_dup_from,
        from_d: CRYPTO_EX_dup_from_d,
        idx: c_int,
        argl: c_long,
        argp: *mut c_void,
    ) -> c_int,
>;
pub type CRYPTO_EX_free = Option<
    unsafe extern "C" fn(
        parent: *mut c_void,
        ptr: *mut c_void,
        ad: *mut CRYPTO_EX_DATA,
        idx: c_int,
        argl: c_long,
        argp: *mut c_void,
    ),
>;

#[cfg(any(ossl110, libressl390))]
#[inline]
#[track_caller]
pub unsafe fn OPENSSL_malloc(num: usize) -> *mut c_void {
    CRYPTO_malloc(
        num,
        concat!(file!(), "\0").as_ptr() as *const _,
        line!() as _,
    )
}

#[cfg(not(any(ossl110, libressl390)))]
#[inline]
#[track_caller]
pub unsafe fn OPENSSL_malloc(num: c_int) -> *mut c_void {
    CRYPTO_malloc(
        num,
        concat!(file!(), "\0").as_ptr() as *const _,
        line!() as _,
    )
}

#[cfg(any(ossl110, libressl390))]
#[inline]
#[track_caller]
pub unsafe fn OPENSSL_free(addr: *mut c_void) {
    CRYPTO_free(
        addr,
        concat!(file!(), "\0").as_ptr() as *const _,
        line!() as _,
    )
}

#[cfg(not(any(ossl110, libressl390)))]
#[inline]
pub unsafe fn OPENSSL_free(addr: *mut c_void) {
    CRYPTO_free(addr)
}

#[cfg(not(ossl110))]
pub const CRYPTO_LOCK_X509: c_int = 3;
#[cfg(not(ossl110))]
pub const CRYPTO_LOCK_EVP_PKEY: c_int = 10;
#[cfg(not(ossl110))]
pub const CRYPTO_LOCK_SSL_CTX: c_int = 12;
#[cfg(not(ossl110))]
pub const CRYPTO_LOCK_SSL_SESSION: c_int = 14;

cfg_if! {
    if #[cfg(any(ossl110, libressl381))] {
        pub const CRYPTO_EX_INDEX_SSL: c_int = 0;
        pub const CRYPTO_EX_INDEX_SSL_CTX: c_int = 1;
    } else if #[cfg(libressl)] {
        pub const CRYPTO_EX_INDEX_SSL: c_int = 1;
        pub const CRYPTO_EX_INDEX_SSL_CTX: c_int = 2;
    }
}

cfg_if! {
    if #[cfg(any(ossl110, libressl271))] {
        pub const OPENSSL_VERSION: c_int = 0;
        pub const OPENSSL_CFLAGS: c_int = 1;
        pub const OPENSSL_BUILT_ON: c_int = 2;
        pub const OPENSSL_PLATFORM: c_int = 3;
        pub const OPENSSL_DIR: c_int = 4;
    } else {
        pub const SSLEAY_VERSION: c_int = 0;
        pub const SSLEAY_CFLAGS: c_int = 2;
        pub const SSLEAY_BUILT_ON: c_int = 3;
        pub const SSLEAY_PLATFORM: c_int = 4;
        pub const SSLEAY_DIR: c_int = 5;
    }
}

pub const CRYPTO_LOCK: c_int = 1;
