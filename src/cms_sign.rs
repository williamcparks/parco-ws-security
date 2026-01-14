use base64::Engine;
use cms::{
    cert::CertificateChoices,
    content_info::{CmsVersion, ContentInfo},
    signed_data::{
        CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData,
        SignerIdentifier, SignerInfo,
    },
};
use const_oid::db::rfc5911::{ID_DATA, ID_SIGNED_DATA};
use der::{Any, Encode, asn1::OctetString};
use rsa::{
    RsaPrivateKey,
    pkcs1v15::SigningKey,
    signature::{SignatureEncoding, Signer},
};
use sha2::Sha256;
use thiserror::Error;
use x509_cert::{Certificate, der::Decode, spki::AlgorithmIdentifierOwned};

/// A Crypto Message Syntax Signer
/// Uses A Certificate PEM and RsaPrivateKey To Sign Data
/// Digest Algorithm is sha256 and Signature Algo is Rsa Encryption
pub struct CmsSign {
    pub cert: Certificate,
    pub rsa_private_key: RsaPrivateKey,
}

impl CmsSign {
    /// use a certificate pem file that starts with "-----BEGIN CERTIFICATE-----"
    /// and a [`RsaPrivateKey`] to create a [`CmsSign`]
    pub fn try_new(cert_pem: &str, rsa_private_key: RsaPrivateKey) -> Result<Self, CmsSignError> {
        let cert_der = pem::parse(cert_pem)?;
        let cert = Certificate::from_der(cert_der.contents())?;

        Ok(Self {
            cert,
            rsa_private_key,
        })
    }

    /// sign the bytes of data using the Cms Signing Configuration from before
    pub fn try_sign_base64(&self, data: &[u8]) -> Result<String, CmsSignError> {
        let econtent = OctetString::new(data)?.to_der()?;
        let eci = EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: Some(Any::from_der(&econtent)?),
        };

        let signing_key: SigningKey<Sha256> = SigningKey::new(self.rsa_private_key.clone());
        let signature = signing_key.sign(data);
        let signature_bytes = signature.to_vec();

        let signer_info = self.create_signer_info(&signature_bytes)?;

        let cert_der = self.cert.to_der()?;

        let cert_choice = CertificateChoices::Certificate(Certificate::from_der(&cert_der)?);
        let certificates = Some(CertificateSet::try_from(vec![cert_choice])?);

        let digest_alg_id = AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };

        let digest_algorithms = DigestAlgorithmIdentifiers::try_from(vec![digest_alg_id])?;

        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms,
            encap_content_info: eci,
            certificates,
            crls: None,
            signer_infos: vec![signer_info].try_into()?,
        };

        let content_info = ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::from_der(&signed_data.to_der()?)?,
        };

        let output_bytes = content_info.to_der()?;

        let b64 = base64::engine::general_purpose::STANDARD.encode(output_bytes.as_slice());

        Ok(b64)
    }

    fn create_signer_info(&self, signature: &[u8]) -> Result<SignerInfo, CmsSignError> {
        let issuer = self.cert.tbs_certificate.issuer.clone();
        let serial_number = self.cert.tbs_certificate.serial_number.clone();

        let sid = SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
            issuer,
            serial_number,
        });

        let digest_alg = AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };

        let signature_algorithm = AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
            parameters: None,
        };

        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid,
            digest_alg,
            signed_attrs: None,
            signature_algorithm,
            signature: OctetString::new(signature)?,
            unsigned_attrs: None,
        };

        Ok(signer_info)
    }
}

/// An error during signing or creation of a signer
#[derive(Debug, Error)]
pub enum CmsSignError {
    /// a pem parsing / serialization error
    #[error(transparent)]
    Pem(#[from] pem::PemError),

    /// a der parsing / serialization error
    #[error(transparent)]
    Der(#[from] der::Error),
}
