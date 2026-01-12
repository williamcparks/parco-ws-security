use parco_xml::xml;

use crate::{SignedInfo, Timestamp};

/// Represents a complete WS-Security SOAP header.
#[derive(Clone, Debug)]
pub struct Security<'a> {
    /// Timestamp defining the message validity window.
    pub timestamp: Timestamp,
    /// Base64-encoded X.509 certificate.
    pub binary_security_token: &'a str,
    /// XML Signature metadata referencing the timestamp.
    pub signed_info: SignedInfo,
    /// Base64-encoded RSA signature value.
    pub signature: String,
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
            wssu:Id="_1" {
                (self.binary_security_token)
            }

        dsig:Signature {
            (self.signed_info.display())

            dsig:SignatureValue {
                (self.signature)
            }

            dsig:KeyInfo {
                wsse:SecurityTokenReference {
                    wsse:Reference
                        URI="#_1"
                        ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" {}
                }
            }
        }
    }
}
