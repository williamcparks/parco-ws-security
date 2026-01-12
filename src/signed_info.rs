use base64::Engine;
use parco_xml::{Xml, xml};
use sha1::{Digest, Sha1};

use crate::Timestamp;

/// XML Signature metadata containing the digest of the signed content.
#[derive(Clone, Debug)]
pub struct SignedInfo {
    /// Base64-encoded SHA-1 digest of the referenced XML.
    pub digest_value: String,
}

impl SignedInfo {
    /// Computes a digest over the canonicalized timestamp XML.
    pub fn new(timestamp: &Timestamp) -> Self {
        let xml = timestamp.xml();

        let mut hasher = Sha1::new();
        hasher.update(xml.as_bytes());
        let digest = hasher.finalize();
        let digest_value = base64::engine::general_purpose::STANDARD.encode(digest);

        Self { digest_value }
    }
}

xml! {
    use SignedInfo;

    @ns {
        dsig = "http://www.w3.org/2000/09/xmldsig#",
    }

    dsig:SignedInfo {
        dsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" {}
        dsig:SignatureMethod  Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" {}
        dsig:Reference URI="#_0" {
            dsig:Transforms {
                dsig:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" {}
            }
            dsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" {}
            dsig:DigestValue {
                (self.digest_value)
            }
        }
    }
}
