//! Internal bundled schema used by the workspace and tests.

use crate::schema::AuthSchema;

pub struct BundledSchema;

impl AuthSchema for BundledSchema {
    type User = crate::store::entities::user::Model;
    type Session = crate::store::entities::session::Model;
    type Account = crate::store::entities::account::Model;
    type Verification = crate::store::entities::verification::Model;
}
