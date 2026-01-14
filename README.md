# WS-Security SOAP Helper Library

This Rust library provides utilities for constructing WS-Security headers with XML signatures, timestamps, and X.509 certificate support, suitable for SOAP messages.

## Overview

The library allows you to:

- Generate WS-Security headers with timestamps and digital signatures.
- Sign SOAP messages using RSA private keys or signing keys.
- Easily integrate cryptographic utilities such as SHA-1, RSA, and Base64 encoding.

## Features

[✅] - _"cms-sign"_ adds support for Crypto Message Syntax via Sha256 Digest + Rsa Signature

### Example

```rust,ignore
use parco_ws_security::{
    Security,
    crypto::{
        rsa::{
            RsaPrivateKey, pkcs8::DecodePrivateKey
        },
        sha1::Sha1
    }
};

const PRIVATE_KEY_PEM: &str = include_str!("YOUR_PRIVATE_KEY.pem");
const CERTIFICATE_BASE64: &str = include_str!("CERT_BASE64.txt");

/// if you're key is pkcs8 use this else refer to [`rsa`] documentation for parsing your key
let private_key = RsaPrivateKey::from_pkcs8_pem(PRIVATE_KEY_PEM).unwrap();
let security_header = Security::new_with_private_key(CERTIFICATE_BASE64, private_key);
```

## Cms-Sign

The "cms-sign" feature enables

```rust,ignore
use parco_ws_security::crypto::{CmsSign, chrono::Utc, rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey}};

let cert_pem = include_str!("CERT_PEM");
let private_key_pem = include_str!("PKEY_PEM");
let rsa_private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem).unwrap();

let cms_sign = CmsSign::try_new(cert_pem, rsa_private_key).unwrap();

let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);

println!(
    "{}",
    cms_sign.try_sign_base64(timestamp.as_bytes()).unwrap()
);
```
