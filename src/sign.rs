use base64::Engine;
use parco_xml::Xml;
use rsa::{
    RsaPrivateKey,
    pkcs1v15::SigningKey,
    signature::{SignatureEncoding, Signer},
};
use sha1::Sha1;

use crate::SignedInfo;

impl SignedInfo {
    /// Signs the canonicalized XML using an RSA private key.
    pub fn sign_with_private_key(&self, private_key: RsaPrivateKey) -> String {
        let signing_key = SigningKey::<Sha1>::new(private_key);
        self.sign_with_signing_key(&signing_key)
    }

    /// Signs the canonicalized XML using an existing signing key.
    pub fn sign_with_signing_key(&self, signing_key: &SigningKey<Sha1>) -> String {
        let xml = self.xml();
        let signature_bytes = signing_key.sign(xml.as_bytes());

        base64::engine::general_purpose::STANDARD.encode(signature_bytes.to_bytes())
    }
}
