use crate::cvt;
use crate::cvt_p;
use crate::error::ErrorStack;
use crate::mac::Mac;
use foreign_types::ForeignType;
use openssl_macros::corresponds;
use std::ffi::CStr;
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::EVP_MAC_CTX;
    fn drop = ffi::EVP_MAC_CTX_free;
    fn clone = ffi::EVP_MAC_CTX_dup;

    /// A context object used to perform MAC operations.
    pub struct MacCtx;
    /// A reference to a [`HmacCtx`].
    pub struct MacCtxRef;
}

impl MacCtx {
    /// Creates a new context.
    #[corresponds(EVP_MAC_CTX_new)]
    pub fn new(mac: Mac) -> Result<Self, ErrorStack> {
        ffi::init();

        unsafe {
            let ptr = cvt_p(ffi::EVP_MAC_CTX_new(mac.as_ptr()))?;
            Ok(MacCtx::from_ptr(ptr))
        }
    }

    /// Set key and digest
    pub fn init_ex(&mut self, key: Option<&[u8]>, md: &CStr) -> Result<(), ErrorStack> {
        let key_field_name = c"key";
        let digest_field_name = c"digest";

        let key_len = key.map(|v| v.len()).unwrap_or_default();
        let key = key.map(|v| v.as_ptr()).unwrap_or(ptr::null());

        unsafe {
            let param_key =
                ffi::OSSL_PARAM_construct_octet_string(key_field_name.as_ptr(), key as _, key_len);
            let param_digest = ffi::OSSL_PARAM_construct_utf8_string(
                digest_field_name.as_ptr(),
                md.as_ptr() as _,
                md.to_bytes().len(),
            );
            let param_end = ffi::OSSL_PARAM_construct_end();

            let params = [param_key, param_digest, param_end];

            cvt(ffi::EVP_MAC_CTX_set_params(self.as_ptr(), params.as_ptr()))?;
        }
        Ok(())
    }

    /// Returns the MAC output size for the given context.
    #[corresponds(EVP_MAC_CTX_get_mac_size)]
    pub fn mac_size(&self) -> usize {
        unsafe { ffi::EVP_MAC_CTX_get_mac_size(self.as_ptr()) }
    }

    /// Returns the MAC block size for the given context.
    ///
    /// Not all MAC algorithms support this.
    #[corresponds(EVP_MAC_CTX_get_block_size)]
    pub fn block_size(&self) -> usize {
        unsafe { ffi::EVP_MAC_CTX_get_block_size(self.as_ptr()) }
    }

    /// Add data bytes to the MAC input.
    #[corresponds(EVP_MAC_update)]
    #[inline]
    pub fn mac_update(&mut self, data: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_MAC_update(
                self.as_ptr(),
                data.as_ptr() as *const _,
                data.len(),
            ))?;
        }

        Ok(())
    }

    /// Do the final computation and stores the result.
    ///
    /// If `out` is set to `None`, an upper bound on the number of bytes required for the output buffer will be
    /// returned.
    #[corresponds(EVP_MAC_final)]
    #[inline]
    pub fn mac_final(&mut self, out: Option<&mut [u8]>) -> Result<usize, ErrorStack> {
        let mut len = out.as_ref().map_or(0, |b| b.len());

        unsafe {
            cvt(ffi::EVP_MAC_final(
                self.as_ptr(),
                out.map_or(ptr::null_mut(), |b| b.as_mut_ptr()),
                &mut len,
                len,
            ))?;
        }

        Ok(len)
    }

    /// Like [`Self::mac_final`] but appends the result to a [`Vec`].
    pub fn mac_final_to_vec(&mut self, out: &mut Vec<u8>) -> Result<usize, ErrorStack> {
        let base = out.len();
        out.resize(base + self.mac_size(), 0);
        let len = self.mac_final(Some(&mut out[base..]))?;
        out.truncate(base + len);
        Ok(len)
    }
}
