use libc::*;

#[allow(unused_imports)]
use super::super::*;

pub enum ASN1_OBJECT {}
pub enum ASN1_VALUE {}

pub type ASN1_BOOLEAN = c_int;
pub enum ASN1_INTEGER {}
pub enum ASN1_ENUMERATED {}
pub enum ASN1_GENERALIZEDTIME {}
pub enum ASN1_STRING {}
pub enum ASN1_BIT_STRING {}
pub enum ASN1_TIME {}
pub enum ASN1_OCTET_STRING {}
pub enum ASN1_NULL {}
pub enum ASN1_PRINTABLESTRING {}
pub enum ASN1_T61STRING {}
pub enum ASN1_IA5STRING {}
pub enum ASN1_GENERALSTRING {}
pub enum ASN1_BMPSTRING {}
pub enum ASN1_UNIVERSALSTRING {}
pub enum ASN1_UTCTIME {}
pub enum ASN1_VISIBLESTRING {}
pub enum ASN1_UTF8STRING {}

pub enum bio_st {} // FIXME remove
cfg_if! {
    if #[cfg(any(ossl110, libressl))] {
        pub enum BIO {}
    } else {
        #[repr(C)]
        pub struct BIO {
            pub method: *mut BIO_METHOD,
            pub callback: Option<
                unsafe extern "C" fn(*mut BIO, c_int, *const c_char, c_int, c_long, c_long) -> c_long,
            >,
            pub cb_arg: *mut c_char,
            pub init: c_int,
            pub shutdown: c_int,
            pub flags: c_int,
            pub retry_reason: c_int,
            pub num: c_int,
            pub ptr: *mut c_void,
            pub next_bio: *mut BIO,
            pub prev_bio: *mut BIO,
            pub references: c_int,
            pub num_read: c_ulong,
            pub num_write: c_ulong,
            pub ex_data: CRYPTO_EX_DATA,
        }
    }
}
cfg_if! {
    if #[cfg(ossl320)] {
        pub enum BIO_ADDR {}
        pub enum BIO_POLL_DESCRIPTOR {}
        #[repr(C)]
        pub struct BIO_MSG {
            pub data: *mut c_void,
            pub data_len: usize,
            pub peer: *mut BIO_ADDR,
            pub local: *mut BIO_ADDR,
            pub flags: u64,
        }
    }
}
cfg_if! {
    if #[cfg(any(ossl110, libressl))] {
        pub enum BIGNUM {}
    } else {
        #[repr(C)]
        pub struct BIGNUM {
            pub d: *mut BN_ULONG,
            pub top: c_int,
            pub dmax: c_int,
            pub neg: c_int,
            pub flags: c_int,
        }
    }
}
pub enum BN_BLINDING {}
pub enum BN_MONT_CTX {}

pub enum BN_CTX {}
pub enum BN_GENCB {}

cfg_if! {
    if #[cfg(any(ossl110, libressl))] {
        pub enum EVP_CIPHER {}
    } else {
        #[repr(C)]
        pub struct EVP_CIPHER {
            pub nid: c_int,
            pub block_size: c_int,
            pub key_len: c_int,
            pub iv_len: c_int,
            pub flags: c_ulong,
            pub init: Option<
                unsafe extern "C" fn(*mut EVP_CIPHER_CTX, *const c_uchar, *const c_uchar, c_int) -> c_int,
            >,
            pub do_cipher: Option<
                unsafe extern "C" fn(*mut EVP_CIPHER_CTX, *mut c_uchar, *const c_uchar, size_t) -> c_int,
            >,
            pub cleanup: Option<unsafe extern "C" fn(*mut EVP_CIPHER_CTX) -> c_int>,
            pub ctx_size: c_int,
            pub set_asn1_parameters:
                Option<unsafe extern "C" fn(*mut EVP_CIPHER_CTX, *mut ASN1_TYPE) -> c_int>,
            pub get_asn1_parameters:
                Option<unsafe extern "C" fn(*mut EVP_CIPHER_CTX, *mut ASN1_TYPE) -> c_int>,
            pub ctrl:
                Option<unsafe extern "C" fn(*mut EVP_CIPHER_CTX, c_int, c_int, *mut c_void) -> c_int>,
            pub app_data: *mut c_void,
        }
    }
}
pub enum EVP_CIPHER_CTX {}
pub enum EVP_MD {}
cfg_if! {
    if #[cfg(any(ossl110, libressl))] {
        pub enum EVP_MD_CTX {}
    } else {
        #[repr(C)]
        pub struct EVP_MD_CTX {
            digest: *mut EVP_MD,
            engine: *mut ENGINE,
            flags: c_ulong,
            md_data: *mut c_void,
            pctx: *mut EVP_PKEY_CTX,
            update: *mut c_void,
        }
    }
}

pub enum PKCS8_PRIV_KEY_INFO {}

pub enum EVP_PKEY_ASN1_METHOD {}

pub enum EVP_PKEY_CTX {}

pub enum CMAC_CTX {}

cfg_if! {
    if #[cfg(any(ossl110, libressl))] {
        pub enum HMAC_CTX {}
    } else {
        #[repr(C)]
        pub struct HMAC_CTX {
            md: *mut EVP_MD,
            md_ctx: EVP_MD_CTX,
            i_ctx: EVP_MD_CTX,
            o_ctx: EVP_MD_CTX,
            key_length: c_uint,
            key: [c_uchar; 128],
        }
    }
}

cfg_if! {
    if #[cfg(any(ossl110, libressl))] {
        pub enum DH {}
    } else {
        #[repr(C)]
        pub struct DH {
            pub pad: c_int,
            pub version: c_int,
            pub p: *mut BIGNUM,
            pub g: *mut BIGNUM,
            pub length: c_long,
            pub pub_key: *mut BIGNUM,
            pub priv_key: *mut BIGNUM,
            pub flags: c_int,
            pub method_mont_p: *mut BN_MONT_CTX,
            pub q: *mut BIGNUM,
            pub j: *mut BIGNUM,
            pub seed: *mut c_uchar,
            pub seedlen: c_int,
            pub counter: *mut BIGNUM,
            pub references: c_int,
            pub ex_data: CRYPTO_EX_DATA,
            pub meth: *const DH_METHOD,
            pub engine: *mut ENGINE,
        }
    }
}
pub enum DH_METHOD {}

cfg_if! {
    if #[cfg(any(ossl110, libressl))] {
        pub enum DSA {}
    } else {
        #[repr(C)]
        pub struct DSA {
            pub pad: c_int,
            pub version: c_long,
            pub write_params: c_int,

            pub p: *mut BIGNUM,
            pub q: *mut BIGNUM,
            pub g: *mut BIGNUM,
            pub pub_key: *mut BIGNUM,
            pub priv_key: *mut BIGNUM,
            pub kinv: *mut BIGNUM,
            pub r: *mut BIGNUM,

            pub flags: c_int,
            pub method_mont_p: *mut BN_MONT_CTX,
            pub references: c_int,
            pub ex_data: CRYPTO_EX_DATA,
            pub meth: *const DSA_METHOD,
            pub engine: *mut ENGINE,
        }
    }
}
pub enum DSA_METHOD {}

cfg_if! {
    if #[cfg(any(ossl110, libressl))] {
        pub enum RSA {}
    } else {
        #[repr(C)]
        pub struct RSA {
            pub pad: c_int,
            pub version: c_long,
            pub meth: *const RSA_METHOD,

            pub engine: *mut ENGINE,
            pub n: *mut BIGNUM,
            pub e: *mut BIGNUM,
            pub d: *mut BIGNUM,
            pub p: *mut BIGNUM,
            pub q: *mut BIGNUM,
            pub dmp1: *mut BIGNUM,
            pub dmq1: *mut BIGNUM,
            pub iqmp: *mut BIGNUM,

            pub ex_data: CRYPTO_EX_DATA,
            pub references: c_int,
            pub flags: c_int,

            pub _method_mod_n: *mut BN_MONT_CTX,
            pub _method_mod_p: *mut BN_MONT_CTX,
            pub _method_mod_q: *mut BN_MONT_CTX,

            pub bignum_data: *mut c_char,
            pub blinding: *mut BN_BLINDING,
            pub mt_blinding: *mut BN_BLINDING,
        }
    }
}
pub enum RSA_METHOD {}

pub enum EC_KEY {}

cfg_if! {
    if #[cfg(any(ossl110, libressl))] {
        pub enum X509 {}
    } else {
        #[repr(C)]
        pub struct X509 {
            pub cert_info: *mut X509_CINF,
            pub sig_alg: *mut X509_ALGOR,
            pub signature: *mut ASN1_BIT_STRING,
            pub valid: c_int,
            pub references: c_int,
            pub name: *mut c_char,
            pub ex_data: CRYPTO_EX_DATA,
            pub ex_pathlen: c_long,
            pub ex_pcpathlen: c_long,
            pub ex_flags: c_ulong,
            pub ex_kusage: c_ulong,
            pub ex_xkusage: c_ulong,
            pub ex_nscert: c_ulong,
            skid: *mut c_void,
            akid: *mut c_void,
            policy_cache: *mut c_void,
            crldp: *mut c_void,
            altname: *mut c_void,
            nc: *mut c_void,
            #[cfg(not(osslconf = "OPENSSL_NO_RFC3779"))]
            rfc3779_addr: *mut c_void,
            #[cfg(not(osslconf = "OPENSSL_NO_RFC3779"))]
            rfc3779_asid: *mut c_void,
            #[cfg(not(osslconf = "OPENSSL_NO_SHA"))]
            sha1_hash: [c_uchar; 20],
            aux: *mut c_void,
        }
    }
}
cfg_if! {
    if #[cfg(any(ossl110, libressl382))] {
        pub enum X509_ALGOR {}
    } else {
        #[repr(C)]
        pub struct X509_ALGOR {
            pub algorithm: *mut ASN1_OBJECT,
            parameter: *mut c_void,
        }
    }
}

stack!(stack_st_X509_ALGOR);

pub enum X509_LOOKUP_METHOD {}

pub enum X509_NAME {}

pub enum X509_PUBKEY {}

cfg_if! {
    if #[cfg(any(ossl110, libressl))] {
        pub enum X509_STORE {}
    } else {
        #[repr(C)]
        pub struct X509_STORE {
            cache: c_int,
            pub objs: *mut stack_st_X509_OBJECT,
            get_cert_methods: *mut stack_st_X509_LOOKUP,
            param: *mut X509_VERIFY_PARAM,
            verify: Option<extern "C" fn(ctx: *mut X509_STORE_CTX) -> c_int>,
            verify_cb: Option<extern "C" fn(ok: c_int, ctx: *mut X509_STORE_CTX) -> c_int>,
            get_issuer: Option<
                extern "C" fn(issuer: *mut *mut X509, ctx: *mut X509_STORE_CTX, x: *mut X509) -> c_int,
            >,
            check_issued:
                Option<extern "C" fn(ctx: *mut X509_STORE_CTX, x: *mut X509, issuer: *mut X509) -> c_int>,
            check_revocation: Option<extern "C" fn(ctx: *mut X509_STORE_CTX) -> c_int>,
            get_crl: Option<
                extern "C" fn(ctx: *mut X509_STORE_CTX, crl: *mut *mut X509_CRL, x: *mut X509) -> c_int,
            >,
            check_crl: Option<extern "C" fn(ctx: *mut X509_STORE_CTX, crl: *mut X509_CRL) -> c_int>,
            cert_crl:
                Option<extern "C" fn(ctx: *mut X509_STORE_CTX, crl: *mut X509_CRL, x: *mut X509) -> c_int>,
            lookup_certs:
                Option<extern "C" fn(ctx: *mut X509_STORE_CTX, nm: *const X509_NAME) -> *mut stack_st_X509>,
            lookup_crls: Option<
                extern "C" fn(ctx: *const X509_STORE_CTX, nm: *const X509_NAME) -> *mut stack_st_X509_CRL,
            >,
            cleanup: Option<extern "C" fn(ctx: *mut X509_STORE_CTX) -> c_int>,
            ex_data: CRYPTO_EX_DATA,
            references: c_int,
        }
    }
}

pub enum X509_STORE_CTX {}
pub enum X509_VERIFY_PARAM {}
pub enum X509_OBJECT {}
pub enum X509_LOOKUP {}

#[repr(C)]
pub struct X509V3_CTX {
    flags: c_int,
    issuer_cert: *mut c_void,
    subject_cert: *mut c_void,
    subject_req: *mut c_void,
    crl: *mut c_void,
    #[cfg(not(libressl400))]
    db_meth: *mut c_void,
    db: *mut c_void,
    #[cfg(ossl300)]
    issuer_pkey: *mut c_void,
    // I like the last comment line, it is copied from OpenSSL sources:
    // Maybe more here
}
pub enum CONF {}
#[cfg(ossl110)]
pub enum OPENSSL_INIT_SETTINGS {}

pub enum ENGINE {}
pub enum SSL {}
pub enum SSL_CTX {}

cfg_if! {
    if #[cfg(ossl320)] {
        #[repr(C)]
        pub struct SSL_CONN_CLOSE_INFO {
            pub error_code: u64,
            pub frame_type: u64,
            pub reason: *const ::libc::c_char,
            pub reason_len: usize,
            pub flags: u32,
        }
        #[repr(C)]
        pub struct SSL_SHUTDOWN_EX_ARGS {
            pub quic_error_code: u64,
            pub quic_reason: *const c_char,
        }
        #[repr(C)]
        pub struct SSL_STREAM_RESET_ARGS {
            pub quic_error_code: u64,
        }
    }
}

pub enum COMP_CTX {}

cfg_if! {
    if #[cfg(all(any(ossl110, libressl), not(osslconf = "OPENSSL_NO_COMP")))] {
        pub enum COMP_METHOD {}
    } else if #[cfg(not(osslconf = "OPENSSL_NO_COMP"))] {
        #[repr(C)]
        pub struct COMP_METHOD {
            pub type_: c_int,
            pub name: *const c_char,
            init: Option<unsafe extern "C" fn(*mut COMP_CTX) -> c_int>,
            finish: Option<unsafe extern "C" fn(*mut COMP_CTX)>,
            compress: Option<
                unsafe extern "C" fn(
                    *mut COMP_CTX,
                    *mut c_uchar,
                    c_uint,
                    *mut c_uchar,
                    c_uint,
                ) -> c_int,
            >,
            expand: Option<
                unsafe extern "C" fn(
                    *mut COMP_CTX,
                    *mut c_uchar,
                    c_uint,
                    *mut c_uchar,
                    c_uint,
                ) -> c_int,
            >,
            ctrl: Option<unsafe extern "C" fn() -> c_long>,
            callback_ctrl: Option<unsafe extern "C" fn() -> c_long>,
        }
    }
}

cfg_if! {
    if #[cfg(any(ossl110, libressl))] {
        pub enum CRYPTO_EX_DATA {}
    } else {
        #[repr(C)]
        pub struct CRYPTO_EX_DATA {
            pub sk: *mut stack_st_void,
            pub dummy: c_int,
        }
    }
}

pub enum OCSP_RESPONSE {}

#[cfg(ossl300)]
pub enum OSSL_PROVIDER {}

#[cfg(ossl300)]
pub enum OSSL_LIB_CTX {}

#[cfg(ossl300)]
#[repr(C)]
pub struct OSSL_PARAM {
    key: *const c_char,
    data_type: c_uint,
    data: *mut c_void,
    data_size: size_t,
    return_size: size_t,
}

#[cfg(ossl300)]
pub enum OSSL_PARAM_BLD {}

#[cfg(ossl300)]
pub enum EVP_KDF {}
#[cfg(ossl300)]
pub enum EVP_KDF_CTX {}

#[cfg(ossl300)]
pub enum OSSL_ENCODER_CTX {}
#[cfg(ossl300)]
pub enum OSSL_DECODER_CTX {}

#[cfg(ossl300)]
pub type OSSL_PASSPHRASE_CALLBACK = Option<
    unsafe extern "C" fn(
        pass: *mut c_char,
        pass_size: size_t,
        pass_len: *mut size_t,
        params: *const OSSL_PARAM,
        arg: *mut c_void,
    ) -> c_int,
>;

#[cfg(ossl300)]
pub enum EVP_MAC {}
#[cfg(ossl300)]
pub enum EVP_MAC_CTX {}
