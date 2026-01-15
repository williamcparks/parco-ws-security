use std::fmt::Display;

use rand::Rng;
use uuid::Uuid;

/// A cheap copiable type for wssu ids used in ws-security headers
/// [`WSSUId::new`] generates a new one
/// [`WSSUId::with_hash`] returns a displayable type that formats as `#uuid-{id}-{random 3 digits}`
/// [`WSSUId::no_hash`] returns a displayable type that formats as `uuid-{id}-{random 3 digits}`
#[derive(Clone, Copy, Debug)]
pub struct WSSUId {
    pub uuid: Uuid,
    pub ending: u32,
}

impl WSSUId {
    /// generate a new WSSUId
    pub fn new() -> Self {
        let uuid = Uuid::new_v4();
        let mut rng = rand::rng();
        let ending: u32 = rng.random_range(100..1000);
        WSSUId { uuid, ending }
    }

    /// get a displayable type that formats as `uuid-{id}-{random 3 digits}`
    pub fn no_hash(self) -> NoHash {
        NoHash(self.uuid, self.ending)
    }

    /// get a displayable type that formats as `#uuid-{id}-{random 3 digits}`
    pub fn with_hash(self) -> WithHash {
        WithHash(self.uuid, self.ending)
    }
}

pub struct NoHash(pub Uuid, pub u32);

impl Display for NoHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "uuid-{}-{}", self.0, self.1)
    }
}

pub struct WithHash(pub Uuid, pub u32);

impl Display for WithHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#uuid-{}-{}", self.0, self.1)
    }
}

impl Default for WSSUId {
    fn default() -> Self {
        Self::new()
    }
}
