use chrono::{DateTime, Duration, SecondsFormat, Utc};
use parco_xml::xml;

/// WS-Security timestamp defining message creation and expiration.
#[derive(Clone, Debug)]
pub struct Timestamp {
    /// UTC time when the message was created.
    pub created: DateTime<Utc>,
    /// UTC time when the message expires.
    pub expires: DateTime<Utc>,
    /// the uuid used for the wssu:Id field, from [`uuid`](crate::BinarySecurityToken::uuid)
    pub uuid_with_hash: String,
}

impl Timestamp {
    /// Creates a timestamp valid for the given duration from now. and a uuid from [`uuid`](crate::BinarySecurityToken::uuid)
    pub fn now(expires_in: Duration, uuid_with_hash: String) -> Self {
        let now = Utc::now();
        Self {
            created: now,
            expires: now + expires_in,
            uuid_with_hash,
        }
    }
}

xml! {
    use Timestamp;

    @ns {
        wssu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    }

    wssu:Timestamp wssu:Id=(&self.uuid_with_hash[1..]) {
        wssu:Created { (self.created.to_rfc3339_opts(SecondsFormat::Millis, true)) }
        wssu:Expires { (self.expires.to_rfc3339_opts(SecondsFormat::Millis, true)) }
    }
}
