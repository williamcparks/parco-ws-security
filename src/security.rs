use parco_xml::xml;

use crate::{SignedInfo, Timestamp};

/// Represents a complete WS-Security SOAP header.
#[derive(Clone, Debug)]
pub struct Security<'a> {
    /// Timestamp defining the message validity window.
    pub timestamp: Timestamp,
    /// Base64-encoded X.509 certificate.
    pub binary_security_token: BinarySecurityToken<'a>,
    /// XML Signature metadata referencing the timestamp.
    pub signed_info: SignedInfo,
    /// Base64-encoded RSA signature value.
    pub signature: String,
}

/// Represents the binary security token header
///
/// the easiest way to build it is via [`BinarySecurityToken::new`] which takes care of uuid's for you
///
/// you can also build [`BinarySecurityToken::uuid_with_hash`] using the [`BinarySecurityToken::uuid`]
/// function and using the *get* method as described below
///
/// "uuid_with_hash" should be built like the following:
///
/// generate a uuid such as: 2701275a-71b1-4fb4-9835-e2b25yT78d21
/// add the uuid and # prefix and 3 random digits suffix i.e: #uuid-{id_from_prev_step}-123
/// assign [`BinarySecurityToken::uuid_with_hash`] to this value
#[derive(Clone, Debug)]
pub struct BinarySecurityToken<'a> {
    /// the actual base64 cert
    pub binary_security_token: &'a str,
    /// the full uuid with hash #uuid-{id}-[random 3 digits]
    pub uuid_with_hash: String,
}

xml! {
    ref Security;

    @ns {
        dsig = "http://www.w3.org/2000/09/xmldsig#",
        soap = "http://schemas.xmlsoap.org/soap/envelope/",
        wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
        wssu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
    }

    wsse:Security soap:mustUnderstand="1" {
        (self.timestamp.display())

        wsse:BinarySecurityToken
            EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
            ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
            wssu:Id=(&self.binary_security_token.uuid_with_hash[1..]) {
                (self.binary_security_token.binary_security_token)
            }

        dsig:Signature {
            (self.signed_info.display())

            dsig:SignatureValue {
                (self.signature)
            }

            dsig:KeyInfo {
                wsse:SecurityTokenReference {
                    wsse:Reference
                        URI=(self.binary_security_token.uuid_with_hash)
                        ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" {}
                }
            }
        }
    }
}

impl<'a> BinarySecurityToken<'a> {
    /// construct a new BinarySecurityToken via the base64 cert and generates uuids for you
    pub fn new(binary_security_token: &'a str) -> Self {
        Self {
            binary_security_token,
            uuid_with_hash: Self::uuid(),
        }
    }

    /// generate a uuid with "#uuid" prefix and "-123" random 3 digits after
    pub fn uuid() -> String {
        use std::fmt::Write;

        use rand::prelude::*;

        let base = uuid::Uuid::new_v4();

        //                                   "#uuid-" +  base uuid length (36) + "-" + 3 digits
        let mut out = String::with_capacity(46);
        out.push_str("#uuid-");
        let _ = write!(&mut out, "{}", base);
        out.push('-');

        let mut rng = rand::rng();
        let random_3_digit_number: u32 = rng.random_range(100..1000);
        let _ = write!(&mut out, "{}", random_3_digit_number);

        out
    }
}
