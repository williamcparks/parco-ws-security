#![doc = include_str!("../README.md")]

mod new_with_key;
mod security;
mod sign;
mod signed_info;
mod timestamp;

pub use security::Security;
pub use signed_info::SignedInfo;
pub use timestamp::Timestamp;

pub mod crypto {
    //! Cryptographic dependency re-exports for consumers.

    pub use base64;
    pub use chrono;
    pub use rsa;
    pub use sha1;
}
