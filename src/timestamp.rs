use chrono::{DateTime, Duration, SecondsFormat, Utc};
use parco_xml::xml;

/// WS-Security timestamp defining message creation and expiration.
#[derive(Clone, Debug)]
pub struct Timestamp {
    /// UTC time when the message was created.
    pub created: DateTime<Utc>,
    /// UTC time when the message expires.
    pub expires: DateTime<Utc>,
}

impl Timestamp {
    /// Creates a timestamp valid for the given duration from now.
    pub fn now(expires_in: Duration) -> Self {
        let now = Utc::now();
        Self {
            created: now,
            expires: now + expires_in,
        }
    }
}

xml! {
    use Timestamp;

    @ns {
        wssu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    }

    wssu:Timestamp wssu:Id="_0" {
        wssu:Created { (self.created.to_rfc3339_opts(SecondsFormat::Millis, true)) }
        wssu:Expires { (self.expires.to_rfc3339_opts(SecondsFormat::Millis, true)) }
    }
}
