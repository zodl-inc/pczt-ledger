//! Running the engine's state machines over a blocking [`Transport`].
//!
//! [`crate::session`] and [`crate::pairing`] perform no I/O, so every
//! embedding needs a loop that moves their commands across a wire. This module
//! is that loop for the blocking [`Transport`] trait: [`run_session`] and
//! [`sign`] drive a [`LedgerSignSession`], and [`query`] runs a one-shot
//! pairing command with the `0x6901` retry policy applied. An embedding with a
//! different I/O shape (async, or callback-driven) reimplements the loop but
//! keeps the same session semantics, because the policies live on the session:
//! [`LedgerSignSession::next_deadline`] picks the timeout and
//! [`LedgerSignSession::process_response`] owns the retry budget.

use crate::pairing::PairingError;
use crate::session::{
    Deadline, LedgerSignSession, PumpStep, SessionError, SessionStatus, SignOutcome, Stage,
    MAX_CMD_NOT_ACCEPTED_RETRIES,
};
use crate::transport::{Transport, TransportError};

/// A ceremony that did not complete.
///
/// The two sources are kept apart because callers report them differently: a
/// transport failure is a device-availability problem, while a
/// [`SessionError`] is the device's — or this host's — answer to a command
/// that did cross the wire.
#[derive(Debug)]
#[non_exhaustive]
pub enum CeremonyError {
    /// One exchange never made it across the transport.
    Transport {
        /// Which stage of the ceremony was outstanding.
        stage: Stage,
        /// What the transport reported.
        source: TransportError,
    },
    /// The session ended: the device refused, the user declined, or applying
    /// the collected signatures failed.
    Session {
        /// What the session reported.
        source: SessionError,
        /// Whether a fresh session over the same PCZT could succeed. Always
        /// `false` for a failure raised by [`LedgerSignSession::finish`], which
        /// happens after the device is done and cannot be improved by asking it
        /// again.
        restartable: bool,
    },
    /// The session cannot be driven further: a command was handed out whose
    /// reply was never processed — an earlier exchange failed on the
    /// transport — so the pump has nothing new to send and nothing it can
    /// resume. The ceremony has to be restarted with a fresh session.
    NotResumable {
        /// Which stage the outstanding command belongs to.
        stage: Stage,
    },
}

impl core::fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CeremonyError::Transport { stage, source } => {
                write!(f, "during the {stage:?} stage: {source}")
            }
            CeremonyError::Session {
                source,
                restartable,
            } => {
                if *restartable {
                    write!(
                        f,
                        "the device ended the session. Its transaction context is gone, so the \
                         only recovery is a fresh session over the same PCZT: {source}"
                    )
                } else {
                    write!(
                        f,
                        "the device ended the session, and retrying cannot help: {source}"
                    )
                }
            }
            CeremonyError::NotResumable { stage } => write!(
                f,
                "the session has a {stage:?} command outstanding whose reply was never \
                 processed, so it cannot be resumed; restart the ceremony with a fresh session"
            ),
        }
    }
}

impl std::error::Error for CeremonyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CeremonyError::Transport { source, .. } => Some(source),
            CeremonyError::Session { source, .. } => Some(source),
            CeremonyError::NotResumable { .. } => None,
        }
    }
}

/// Drives a [`LedgerSignSession`] to completion over `transport`.
///
/// # Which exchanges wait on the user
///
/// The deadline for each exchange comes from
/// [`LedgerSignSession::next_deadline`]: [`Deadline::UserReview`] from the
/// packet carrying `P2_PCZT_FINISHED` — whose reply arrives only once the
/// transaction review is approved or rejected — through the end of the
/// session, since the `PCZT_SIGN_*` commands on the far side of the review may
/// be gated on further confirmations depending on how the app is built.
///
/// `on_review` is called once, just before the review packet goes out, so the
/// caller can tell the user to look at the device.
///
/// # A session that is not fresh
///
/// `Ok(())` means the session reached [`Stage::Complete`] — either during
/// this call or before it, in which case nothing is exchanged. Every other
/// state is an error, never a silent success: a session that has already
/// failed reports its failure again as [`CeremonyError::Session`], and one
/// with a command outstanding — left that way by an earlier call whose
/// exchange failed on the transport — reports [`CeremonyError::NotResumable`].
/// A caller that retries a ceremony therefore does so with a fresh session,
/// not by calling this again on the old one.
pub fn run_session<F: FnMut()>(
    transport: &mut dyn Transport,
    session: &mut LedgerSignSession,
    mut on_review: F,
) -> Result<(), CeremonyError> {
    loop {
        // Announce the review before its packet goes out, and only once: a
        // `0x6901` resend of the review packet is the same review, which
        // `is_past_review` already reports.
        if session.pending_user_action().is_some() && !session.is_past_review() {
            on_review();
        }

        let apdu = match session.next_step() {
            PumpStep::Send(apdu) => apdu,
            // A reply is owed to a command this runner never got to process:
            // the exchange that carried it failed. Nothing here can recover
            // that, and pretending the session ran would report a ceremony
            // that collected no signatures as successful.
            PumpStep::AwaitingReply => {
                return Err(CeremonyError::NotResumable {
                    stage: session.stage(),
                })
            }
            PumpStep::Done => break,
        };
        let deadline = session.next_deadline();

        let reply = transport.exchange_with(&apdu, deadline).map_err(|source| {
            CeremonyError::Transport {
                stage: session.stage(),
                source,
            }
        })?;

        let status = match session.process_response(&reply) {
            Ok(status) => status,
            Err(source) => {
                return Err(CeremonyError::Session {
                    restartable: session.is_restartable(),
                    source,
                })
            }
        };

        match status {
            SessionStatus::Complete => break,
            // A `0x6901`: `next_step` will hand out the same command again.
            SessionStatus::RetrySameApdu => {}
            SessionStatus::MoreApdus | SessionStatus::AwaitingUserAction { .. } => {}
        }
    }

    // `Done` is also what a dead session answers, so the stage decides.
    if session.stage() == Stage::Complete {
        return Ok(());
    }
    match session.failure() {
        Some(source) => Err(CeremonyError::Session {
            source: source.clone(),
            restartable: session.is_restartable(),
        }),
        // A session hands out `Done` only when complete or failed, so this is
        // unreachable by construction; it is still an error rather than an
        // `Ok(())` for a ceremony that did not complete.
        None => Err(CeremonyError::NotResumable {
            stage: session.stage(),
        }),
    }
}

/// [`run_session`] followed by [`LedgerSignSession::finish`].
pub fn sign<F: FnMut()>(
    transport: &mut dyn Transport,
    mut session: LedgerSignSession,
    on_review: F,
) -> Result<SignOutcome, CeremonyError> {
    run_session(transport, &mut session, on_review)?;
    session.finish().map_err(|source| CeremonyError::Session {
        source,
        // `finish` runs after the device has answered everything, so there is
        // nothing left for a second ceremony to do differently.
        restartable: false,
    })
}

/// A one-shot device query that did not answer.
///
/// The sources are kept apart so a caller can tell "no device" from "the
/// wrong app" from "a device that answered something else".
#[derive(Debug)]
#[non_exhaustive]
pub enum QueryError {
    /// The exchange never crossed the transport.
    Transport {
        /// Which command was outstanding.
        what: &'static str,
        /// What the transport reported.
        source: TransportError,
    },
    /// The device answered, and the answer was a refusal or an unparseable
    /// reply.
    Pairing {
        /// Which command was refused.
        what: &'static str,
        /// What the pairing layer made of the reply.
        source: PairingError,
    },
    /// The device SDK refused the frame `0x6901` more times in a row than the
    /// engine's budget allows. The application never saw any of them.
    RefusedRepeatedly {
        /// Which command was refused.
        what: &'static str,
        /// The budget that was spent.
        attempts: u32,
    },
}

impl core::fmt::Display for QueryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            QueryError::Transport { what, source } => write!(f, "sending {what}: {source}"),
            QueryError::Pairing { what, source } => write!(f, "{what}: {source}"),
            QueryError::RefusedRepeatedly { what, attempts } => write!(
                f,
                "{what}: the device refused the frame {attempts} times running (0x6901)"
            ),
        }
    }
}

impl std::error::Error for QueryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            QueryError::Transport { source, .. } => Some(source),
            QueryError::Pairing { source, .. } => Some(source),
            QueryError::RefusedRepeatedly { .. } => None,
        }
    }
}

/// Sends one stateless command, resending it while the device SDK refuses the
/// frame with `0x6901`.
///
/// `0x6901` is raised by the SDK's legacy I/O layer, not by the app, and means
/// the frame was never delivered — so the command has not been executed and
/// resending it is not a repeat. At most [`MAX_CMD_NOT_ACCEPTED_RETRIES`]
/// resends are attempted, the same budget the session pump applies.
///
/// `parse` is the reply parser; it is re-run on each attempt because it is
/// what recognises the status word. Stateful exchanges do not belong here:
/// [`crate::pairing::VkExchange`] absorbs its own refusals, and the session
/// pump has [`SessionStatus::RetrySameApdu`].
pub fn query<T>(
    transport: &mut dyn Transport,
    apdu: &[u8],
    deadline: Deadline,
    what: &'static str,
    mut parse: impl FnMut(&[u8]) -> Result<T, PairingError>,
) -> Result<T, QueryError> {
    for _ in 0..=MAX_CMD_NOT_ACCEPTED_RETRIES {
        let reply = transport
            .exchange_with(apdu, deadline)
            .map_err(|source| QueryError::Transport { what, source })?;
        match parse(&reply) {
            Err(PairingError::CmdNotAccepted) => continue,
            other => return other.map_err(|source| QueryError::Pairing { what, source }),
        }
    }
    Err(QueryError::RefusedRepeatedly {
        what,
        attempts: MAX_CMD_NOT_ACCEPTED_RETRIES,
    })
}
