//! Polkit authorization for privileged daemon commands.
//!
//! The daemon runs as root and its IPC socket is world-writable so the
//! unprivileged GUI/CLI can monitor. Destructive commands (kill, block,
//! quarantine, shutdown, …) are therefore gated: root and members of the
//! dedicated `ring0` group are allowed directly; everyone else is asked via
//! polkitd, which pops the desktop's authentication dialog (the user enters
//! their password once per session thanks to the `auth_admin_keep` rule in
//! `etc/ring0/polkit/com.ring0.policy`).
//!
//! Fail-secure: any polkit error (no system bus, no polkitd, no agent) denies
//! the action rather than allowing it.

use std::collections::HashMap;

use tracing::{info, warn};
use zbus_polkit::policykit1::{AuthorityProxy, CheckAuthorizationFlags, Subject};

/// Polkit action id — must match `etc/ring0/polkit/com.ring0.policy`.
pub const RING0_CONTROL_ACTION: &str = "com.ring0.security.control";

/// Ask polkitd whether the given Unix process may perform privileged daemon
/// operations. With `AllowUserInteraction` set, polkit blocks while the user
/// answers the desktop authentication prompt.
pub async fn check_authorization(pid: u32, uid: u32) -> bool {
    let conn = match zbus::Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            warn!("polkit: system bus unavailable ({e}) — denying privileged action");
            return false;
        }
    };
    let authority = match AuthorityProxy::new(&conn).await {
        Ok(a) => a,
        Err(e) => {
            warn!("polkit: cannot reach org.freedesktop.PolicyKit1 ({e}) — denying");
            return false;
        }
    };
    // None for start_time/uid lets zbus_polkit read /proc/<pid> itself.
    let subject = match Subject::new_for_owner(pid, None, Some(uid)) {
        Ok(s) => s,
        Err(e) => {
            warn!("polkit: cannot build subject for pid {pid} ({e}) — denying");
            return false;
        }
    };
    let details: HashMap<&str, &str> = HashMap::new();
    match authority
        .check_authorization(
            &subject,
            RING0_CONTROL_ACTION,
            &details,
            CheckAuthorizationFlags::AllowUserInteraction.into(),
            "",
        )
        .await
    {
        Ok(result) => {
            if result.is_authorized {
                info!("polkit: pid {pid} (uid {uid}) authorized for {RING0_CONTROL_ACTION}");
                true
            } else {
                warn!(
                    "polkit: pid {pid} (uid {uid}) NOT authorized for {RING0_CONTROL_ACTION} (challenge={})",
                    result.is_challenge
                );
                false
            }
        }
        Err(e) => {
            warn!("polkit: CheckAuthorization failed ({e}) — denying");
            false
        }
    }
}
