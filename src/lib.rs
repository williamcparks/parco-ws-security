#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod new_with_key;
mod security;
mod sign;
mod signed_info;
mod timestamp;
mod wssu_id;

pub use security::BinarySecurityToken;
pub use security::Security;
pub use signed_info::SignedInfo;
pub use timestamp::Timestamp;

#[cfg(feature = "cms-sign")]
mod cms_sign;

pub mod crypto {
    //! Cryptographic dependency re-exports for consumers.

    pub use base64;
    pub use chrono;
    pub use rsa;
    pub use sha1;

    pub use crate::wssu_id::WSSUId;

    #[cfg_attr(docsrs, doc(cfg(feature = "cms-sign")))]
    #[cfg(feature = "cms-sign")]
    pub use crate::cms_sign::{CmsSign, CmsSignError};
}
