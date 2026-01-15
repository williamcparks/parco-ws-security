use chrono::{DateTime, Duration, SecondsFormat, Utc};
use parco_xml::xml;

use crate::crypto::WSSUId;

/// WS-Security timestamp defining message creation and expiration.
#[derive(Clone, Debug)]
pub struct Timestamp {
    /// UTC time when the message was created.
    pub created: DateTime<Utc>,
    /// UTC time when the message expires.
    pub expires: DateTime<Utc>,
    /// the id used for the wssu:Id field, from [`WSSUId`](crate::crypto::WSSUId)
    pub wssu_id: WSSUId,
}

impl Timestamp {
    /// Creates a timestamp valid for the given duration from now. and a id from [`WSSUId`](crate::crypto::WSSUId)
    pub fn now(expires_in: Duration, wssu_id: WSSUId) -> Self {
        let now = Utc::now();
        Self {
            created: now,
            expires: now + expires_in,
            wssu_id,
        }
    }
}

xml! {
    use Timestamp;

    @ns {
        wssu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    }

    wssu:Timestamp wssu:Id=(self.wssu_id.no_hash()) {
        wssu:Created { (self.created.to_rfc3339_opts(SecondsFormat::Millis, true)) }
        wssu:Expires { (self.expires.to_rfc3339_opts(SecondsFormat::Millis, true)) }
    }
}
