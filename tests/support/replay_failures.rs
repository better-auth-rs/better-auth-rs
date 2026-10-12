#![expect(
    clippy::panic,
    reason = "Unexpected fixture variants and deliberate callback panics must fail or exercise the recorded unwind path."
)]

//! Collect completed comparison failures while capture and setup errors retain their own boundaries.

use std::any::Any;
use std::panic::{UnwindSafe, catch_unwind, resume_unwind};

#[derive(Default)]
pub(crate) struct ReplayFailures {
    failures: Vec<(String, Box<dyn Any + Send>)>,
}

impl ReplayFailures {
    pub(crate) fn record(&mut self, case: &str, compare: impl FnOnce() + UnwindSafe) {
        if let Err(payload) = catch_unwind(compare) {
            eprintln!("Native replay case failed: {case}");
            self.failures.push((case.to_owned(), payload));
        }
    }

    /// Preserve the default panic hook and resume the first original payload after all comparisons.
    pub(crate) fn finish(self) {
        let count = self.failures.len();
        let mut failures = self.failures.into_iter();
        if let Some((case, payload)) = failures.next() {
            eprintln!("{count} native replay cases failed:");
            eprintln!("  {case}");
            for (case, _) in failures {
                eprintln!("  {case}");
            }
            resume_unwind(payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, panic_any};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "The collector must resume the original panic payload after executing later comparisons."
    )]
    fn replay_failures_continue_comparisons_and_resume_the_first_payload() {
        ReplayFailures::default().finish();
        let original = Arc::new("first comparison failure");
        let thrown = original.clone();
        let completed = AtomicUsize::new(0);
        let mut failures = ReplayFailures::default();
        failures.record("first", || panic_any(thrown));
        failures.record("second", || {
            completed.fetch_add(1, Ordering::Relaxed);
        });
        failures.record("third", || {
            completed.fetch_add(1, Ordering::Relaxed);
            panic_any("third comparison failure");
        });
        assert_eq!(completed.load(Ordering::Relaxed), 2);
        let payload = catch_unwind(AssertUnwindSafe(|| failures.finish()))
            .expect_err("A failed comparison must fail the suite");
        let returned = payload
            .downcast::<Arc<&str>>()
            .expect("The collector must preserve the first payload type");
        assert!(Arc::ptr_eq(&original, &returned));
    }
}
