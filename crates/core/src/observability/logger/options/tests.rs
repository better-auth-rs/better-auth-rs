#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use crate::observability::{LogArgument, Logger};
use std::sync::{
    Weak,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct ReentrantSink {
    options: Weak<RwLock<LoggerConfig>>,
    calls: Arc<AtomicUsize>,
    dropped_without_lock: Arc<AtomicBool>,
}

impl LogSink for ReentrantSink {
    fn log(&self, _: LogLevel, _: LogArgument<'_>, _: &[LogArgument<'_>]) -> AuthResult<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let options = self.options.upgrade().expect("options still own this sink");
        assert!(
            options.try_write().is_some(),
            "callback runs outside the lock"
        );
        LoggerOptions(options).set_log(None);
        Ok(())
    }
}

impl Drop for ReentrantSink {
    fn drop(&mut self) {
        let unlocked = self
            .options
            .upgrade()
            .is_some_and(|options| options.try_write().is_some());
        self.dropped_without_lock.store(unlocked, Ordering::SeqCst);
    }
}

#[test]
fn callback_can_remove_itself_and_drop_without_holding_the_options_lock() -> AuthResult<()> {
    let options = LoggerOptions::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    options.set_log(Some(Arc::new(ReentrantSink {
        options: Arc::downgrade(&options.0),
        calls: calls.clone(),
        dropped_without_lock: dropped.clone(),
    })));
    let logger = Logger::new(options.clone())?;
    logger.error("remove this callback", &[])?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(dropped.load(Ordering::SeqCst));
    assert!(options.snapshot().log.is_none());
    logger.error("default sink after removal", &[])?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn property_replacement_drops_the_previous_sink_after_releasing_the_write_lock() {
    for replace_all in [false, true] {
        let options = LoggerOptions::default();
        let dropped = Arc::new(AtomicBool::new(false));
        options.set_log(Some(Arc::new(ReentrantSink {
            options: Arc::downgrade(&options.0),
            calls: Arc::new(AtomicUsize::new(0)),
            dropped_without_lock: dropped.clone(),
        })));
        if replace_all {
            drop(options.replace(LoggerConfig::default()));
        } else {
            options.set_log(None);
        }
        assert!(dropped.load(Ordering::SeqCst));
    }
}
