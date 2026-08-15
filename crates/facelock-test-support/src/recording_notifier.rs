use std::sync::Mutex;

use facelock_core::notify::{Notifier, NotifyEvent};

/// A [`Notifier`] that records every event it is asked to deliver, so tests
/// can assert that a notification was (or was not) emitted.
#[derive(Default)]
pub struct RecordingNotifier {
    events: Mutex<Vec<NotifyEvent>>,
}

impl RecordingNotifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of everything delivered so far, in order.
    pub fn events(&self) -> Vec<NotifyEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl Notifier for RecordingNotifier {
    fn notify(&self, event: &NotifyEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_events_in_order() {
        let notifier = RecordingNotifier::new();
        notifier.notify(&NotifyEvent::Scanning);
        notifier.notify(&NotifyEvent::Failure {
            reason: "no match".into(),
        });
        assert_eq!(
            notifier.events(),
            vec![
                NotifyEvent::Scanning,
                NotifyEvent::Failure {
                    reason: "no match".into()
                }
            ]
        );
    }
}
