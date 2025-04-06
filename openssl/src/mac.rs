use crate::cvt_p;
use crate::error::ErrorStack;
use crate::lib_ctx::LibCtxRef;
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::ffi::CString;
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::EVP_MAC;
    fn drop = ffi::EVP_MAC_free;

    /// A context object used to perform MAC operations.
    pub struct Mac;
    /// A reference to a [`HmacCtx`].
    pub struct MacRef;
}

impl Mac {
    /// Fetches an implementation of a MAC algorithm, given a library context libctx and a set of properties.
    ///
    /// Requires OpenSSL 3.0.0 or newer.
    #[corresponds(EVP_MAC_fetch)]
    pub fn fetch(
        ctx: Option<&LibCtxRef>,
        algorithm: &str,
        properties: Option<&str>,
    ) -> Result<Self, ErrorStack> {
        let algorithm = CString::new(algorithm).unwrap();
        let properties = properties.map(|s| CString::new(s).unwrap());

        unsafe {
            let ptr = cvt_p(ffi::EVP_MAC_fetch(
                ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr),
                algorithm.as_ptr(),
                properties.as_ref().map_or(ptr::null_mut(), |s| s.as_ptr()),
            ))?;

            Ok(Mac::from_ptr(ptr))
        }
    }
}
