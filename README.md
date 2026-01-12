# WS-Security SOAP Helper Library

This Rust library provides utilities for constructing WS-Security headers with XML signatures, timestamps, and X.509 certificate support, suitable for SOAP messages.

## Overview

The library allows you to:

- Generate WS-Security headers with timestamps and digital signatures.
- Sign SOAP messages using RSA private keys or signing keys.
- Easily integrate cryptographic utilities such as SHA-1, RSA, and Base64 encoding.

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
