//! Notification bodies: the rendered form of a [`NotifyEvent`].
//!
//! The auth path reports progress as a `NotifyEvent`; the desktop and terminal
//! notifiers render it through here. This is the only domain built from a
//! foreign event type rather than written at a call site.

use facelock_core::notify::NotifyEvent;

#[cfg(test)]
use super::sample_text as s;
use super::{Message, fill, translate};

/// A notification body.
///
/// Variant and field names are the machine vocabulary: [`Message::machine`]
/// derives its event line from them.
#[derive(Debug, Clone, PartialEq)]
pub enum NotifyMessage {
    NotifyScanning,
    NotifyWelcome { label: String },
    NotifyRecognized { similarity: f32 },
    NotifyAuthFailed { reason: String },
}

impl Message for NotifyMessage {
    fn localized(&self) -> String {
        use NotifyMessage::*;
        match self {
            NotifyScanning => translate("Scanning face..."),
            NotifyWelcome { label } => {
                fill(translate("Welcome, {label}"), &[("label", label.clone())])
            }
            NotifyRecognized { similarity } => fill(
                translate("Face recognized ({similarity})"),
                &[("similarity", format!("{similarity:.2}"))],
            ),
            NotifyAuthFailed { reason } => fill(
                translate("Face auth failed: {reason}"),
                &[("reason", reason.clone())],
            ),
        }
    }
}

impl From<&NotifyEvent> for NotifyMessage {
    fn from(event: &NotifyEvent) -> Self {
        match event {
            NotifyEvent::Scanning => NotifyMessage::NotifyScanning,
            NotifyEvent::Success {
                label: Some(label),
                similarity: _,
            } => NotifyMessage::NotifyWelcome {
                label: label.clone(),
            },
            NotifyEvent::Success {
                label: None,
                similarity,
            } => NotifyMessage::NotifyRecognized {
                similarity: *similarity,
            },
            NotifyEvent::Failure { reason } => NotifyMessage::NotifyAuthFailed {
                reason: reason.clone(),
            },
        }
    }
}

/// One sample per variant, in enum order, for the sweeps in [`super::Samples`].
///
/// The list is flat, so it cannot cycle and cannot name a variant twice
/// without saying so; `VARIANT_COUNT` is what fails the sweep when a new
/// variant is not sampled at all. The compiler's share of this is `localized`
/// above: no wildcard arm, so a variant that renders nothing does not build.
#[cfg(test)]
impl super::Samples for NotifyMessage {
    const VARIANT_COUNT: usize = 4;

    fn samples() -> Vec<Self> {
        use NotifyMessage::*;
        vec![
            NotifyScanning,
            NotifyWelcome { label: s("l") },
            NotifyRecognized { similarity: 0.5 },
            NotifyAuthFailed { reason: s("r") },
        ]
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// NotifyEvent -> NotifyMessage mapping mirrors H4's rendering rules:
    /// a labeled success is a welcome, an unlabeled one shows similarity.
    #[test]
    fn notify_event_mapping() {
        assert_eq!(
            NotifyMessage::from(&NotifyEvent::Scanning),
            NotifyMessage::NotifyScanning
        );
        assert_eq!(
            NotifyMessage::from(&NotifyEvent::Success {
                label: Some("Alice".into()),
                similarity: 0.9
            }),
            NotifyMessage::NotifyWelcome {
                label: "Alice".into()
            }
        );
        assert_eq!(
            NotifyMessage::from(&NotifyEvent::Success {
                label: None,
                similarity: 0.87
            }),
            NotifyMessage::NotifyRecognized { similarity: 0.87 }
        );
        assert_eq!(
            NotifyMessage::from(&NotifyEvent::Failure {
                reason: "no match".into()
            }),
            NotifyMessage::NotifyAuthFailed {
                reason: "no match".into()
            }
        );
    }
}
