use chrono::Duration;
use rsa::{RsaPrivateKey, pkcs1v15::SigningKey};
use sha1::Sha1;

use crate::{BinarySecurityToken, Security, SignedInfo, Timestamp};

impl<'a> Security<'a> {
    /// Constructs a WS-Security header using an RSA private key.
    pub fn new_with_private_key(
        binary_security_token: &'a str,
        private_key: RsaPrivateKey,
    ) -> Self {
        let timestamp_uuid = BinarySecurityToken::uuid();

        let timestamp = Timestamp::now(Duration::minutes(5), timestamp_uuid.clone());
        let signed_info = SignedInfo::new(&timestamp);
        let signature = signed_info.sign_with_private_key(private_key);

        let binary_security_token = BinarySecurityToken::new(binary_security_token);

        Self {
            signed_info,
            timestamp,
            binary_security_token,
            signature,
        }
    }

    /// Constructs a WS-Security header using a preconfigured signing key.
    pub fn new_with_signing_key(
        binary_security_token: &'a str,
        signing_key: &SigningKey<Sha1>,
    ) -> Self {
        let timestamp_uuid = BinarySecurityToken::uuid();

        let timestamp = Timestamp::now(Duration::minutes(5), timestamp_uuid.clone());
        let signed_info = SignedInfo::new(&timestamp);
        let signature = signed_info.sign_with_signing_key(signing_key);

        let binary_security_token = BinarySecurityToken::new(binary_security_token);

        Self {
            signed_info,
            timestamp,
            binary_security_token,
            signature,
        }
    }
}
