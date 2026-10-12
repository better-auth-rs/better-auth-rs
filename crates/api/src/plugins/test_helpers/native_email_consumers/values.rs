use super::*;
use better_auth_core::FieldFunction;
use std::sync::{
    OnceLock, Weak,
    atomic::{AtomicUsize, Ordering},
};

use crate::plugins::test_helpers::verification_consumer_native::object::Root;

fn resolve_owner(owner: &Weak<OnceLock<FieldValue>>) -> AuthResult<FieldValue> {
    owner
        .upgrade()
        .and_then(|owner| owner.get().cloned())
        .ok_or_else(|| AuthError::internal("Native email callback owner was released"))
}

fn callback_trace(trace: &Weak<Trace>) -> AuthResult<Arc<Trace>> {
    trace
        .upgrade()
        .ok_or_else(|| AuthError::internal("Native email observer was released"))
}

pub(crate) fn throwing_value(label: &str) -> FieldValue {
    FieldMap::from([
        ("message".into(), format!("{label}-failure").into()),
        ("nullable".into(), FieldValue::Null),
        ("optional".into(), FieldValue::Undefined),
    ])
    .into()
}

pub(crate) fn native_lower(
    trace: &Arc<Trace>,
    label: &str,
    result: FieldValue,
    failure: FieldValue,
    fail_at: Option<&str>,
) -> Root {
    let root = Root::new("object");
    root.data("label", label.into());
    root.data("calls", 0.into());
    let method = FieldFunction::contextual({
        let trace = Arc::downgrade(trace);
        let owner = root.owner();
        let phase = format!("{label}:call");
        let failure = failure.clone();
        let rejects = fail_at == Some("call");
        move |receiver, arguments| {
            let owner = resolve_owner(&owner)?;
            callback_trace(&trace)?.call(&phase, receiver, &owner, arguments)?;
            let calls: usize = owner.model_property("calls")?.decode()?;
            owner.set_model_property("calls", (calls + 1).into())?;
            if rejects {
                return Err(AuthError::from_thrown(failure.clone()));
            }
            Ok(result.clone())
        }
    });
    root.getter("toLowerCase", false, {
        let trace = Arc::downgrade(trace);
        let owner = root.owner();
        let phase = format!("{label}:get");
        let rejects = fail_at == Some("get");
        move |receiver| {
            callback_trace(&trace)?.call(&phase, receiver, &resolve_owner(&owner)?, &[])?;
            if rejects {
                return Err(AuthError::from_thrown(failure.clone()));
            }
            Ok(method.clone().into())
        }
    });
    root
}

pub(crate) struct SelectedUser {
    pub(crate) root: Root,
    reads: Arc<AtomicUsize>,
}

impl SelectedUser {
    pub(crate) fn reads(&self) -> usize {
        self.reads.load(Ordering::Acquire)
    }
}

pub(crate) fn native_user(
    trace: &Arc<Trace>,
    read: impl Fn(usize) -> AuthResult<FieldValue> + Send + Sync + 'static,
    verified: FieldValue,
) -> SelectedUser {
    let root = Root::new("object");
    for (name, value) in [
        ("id", "owner".into()),
        ("name", "Owner".into()),
        ("image", FieldValue::Null),
        ("createdAt", date(NOW - 60_000)),
        ("updatedAt", date(NOW - 60_000)),
    ] {
        root.data(name, value);
    }
    let reads = Arc::new(AtomicUsize::new(0));
    root.getter("email", true, {
        let trace = Arc::downgrade(trace);
        let owner = root.owner();
        let reads = reads.clone();
        move |receiver| {
            callback_trace(&trace)?.call(
                "user.email:get",
                receiver,
                &resolve_owner(&owner)?,
                &[],
            )?;
            read(reads.fetch_add(1, Ordering::AcqRel) + 1)
        }
    });
    root.getter("emailVerified", true, {
        let trace = Arc::downgrade(trace);
        let owner = root.owner();
        move |receiver| {
            callback_trace(&trace)?.call(
                "user.emailVerified:get",
                receiver,
                &resolve_owner(&owner)?,
                &[],
            )?;
            Ok(verified.clone())
        }
    });
    SelectedUser { root, reads }
}
