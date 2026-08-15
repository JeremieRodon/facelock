//! The one way an in-flight authentication is stopped early.
//!
//! An authentication is a blocking loop over camera frames with a deadline of
//! `recognition.timeout_secs`. Before this existed, nothing could shorten
//! that loop: when the caller went away — a screen locker aborting PAM
//! because the password was typed first, a killed `sudo`, a crashed client —
//! the daemon kept capturing, kept the IR emitter lit, and answered a
//! question nobody was waiting for. An invisible cancellation is
//! indistinguishable from a timeout, and a timeout keeps the camera on
//! (ADR 008 §5).
//!
//! The token makes it visible. It is an `Arc<AtomicBool>`, deliberately: it
//! must be settable from a signal handler ([`signal_hook::flag::register`]
//! takes exactly this type) and from a D-Bus watcher task **without taking
//! the handler mutex**, because the thing being cancelled is holding it.
//!
//! Every loop that can run for a perceptible time — the auth loop, the
//! enroll loop, and both frame-discard loops — checks it once per iteration,
//! so a request ends within one frame of the token being set.
//!
//! **One token per request, minted fresh, never reset.** There is no way to
//! clear a token, because a clearable token has to be shared with somebody
//! else to be worth clearing — and a shared one is cross-talk waiting to
//! happen. zbus dispatches every method call in its own task, so with a
//! single daemon-lifetime token any second call (including one about to be
//! denied) could clear the flag an in-flight request was about to read, and
//! any departure watch registered against it could cancel a request that was
//! never its caller's. A token is created by the request it belongs to,
//! handed to that request's loops and to that request's caller-departure
//! watch, and dropped with it. "Fresh" and "un-cancelled" are then the same
//! statement, which is why arming does not exist.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A shared "stop now" flag for one in-flight request.
///
/// Cloning shares the flag; [`CancelToken::new`] makes a fresh one.
#[derive(Clone, Debug)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A fresh, un-cancelled token.
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Stop the in-flight request. Takes no lock, so it is safe to call from
    /// a signal handler, a D-Bus watcher, or the suspend path while the
    /// request being cancelled holds the handler mutex.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Checked once per loop iteration.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// The raw flag, for `signal_hook::flag::register`, which registers into
    /// an `Arc<AtomicBool>` directly.
    pub fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.0)
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_token_is_not_cancelled() {
        assert!(!CancelToken::new().is_cancelled());
    }

    #[test]
    fn clones_share_one_flag() {
        let token = CancelToken::new();
        let watcher = token.clone();
        watcher.cancel();
        assert!(token.is_cancelled(), "a clone must set the same flag");
    }

    #[test]
    fn the_raw_flag_is_the_same_flag() {
        let token = CancelToken::new();
        // This is the handle `signal_hook::flag::register` writes through.
        token.flag().store(true, Ordering::SeqCst);
        assert!(token.is_cancelled());
    }

    /// The absence of a reset is the design, not an omission: every request
    /// mints its own, so "is this cancelled" is only ever a question about
    /// *this* request, and no other request can answer it.
    #[test]
    fn two_tokens_never_share_a_flag() {
        let first = CancelToken::new();
        let second = CancelToken::new();
        second.cancel();
        assert!(
            !first.is_cancelled(),
            "a second request's cancellation reached the first request"
        );
    }
}
