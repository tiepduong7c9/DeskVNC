//! RDSTLS: the authentication a redirected connection runs in place of
//! CredSSP (MS-RDPBCGR 2.2.17, 5.4.5.3).
//!
//! Three PDUs over the TLS channel the upgrade already established, in a
//! fixed order and with no framing of their own:
//!
//! ```text
//! server -> client   capabilities            8 bytes
//! client -> server   authentication request  variable
//! server -> client   authentication response 10 bytes
//! ```
//!
//! # Why this is not a credential prompt
//!
//! Nothing here comes from the user. Every field was handed to us by the
//! Server Redirection that ended the previous attempt: a redirection GUID, a
//! user name, a domain, and a password encrypted under the public key of the
//! target's certificate. The client holds no half of that key. It forwards
//! the ciphertext and the target decrypts it, which is the whole reason this
//! protocol exists and the reason NLA cannot stand in for it
//! (`docs/RDP_SPEC_NOTES.md` §1.14).
//!
//! A failure here is therefore never the user's password being wrong, and
//! re-prompting for one would spend attempts against a lockout counter for a
//! credential that was never involved. [`authenticate`] returns
//! [`RdpError::AuthFailed`] and the attempt ends.

use rdp_pdu::io::{Decode, Encode, Writer};
use rdp_pdu::rdstls::{RdstlsAuthRequest, RdstlsAuthResponse, RdstlsCapabilities};
use rdp_pdu::Reader;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{ConnectStage, RdpError, Result};
use crate::options::RdstlsCredentials;
use crate::transport::framer::{Expect, Framer};
use crate::transport::with_timeout;

/// How long each of the two reads may take.
///
/// The server has already authenticated the connection this redirection came
/// from, so the only work behind these PDUs is a private key operation and a
/// logon. Fifteen seconds is the same budget the X.224 exchange gets.
pub const RDSTLS_STEP: std::time::Duration = std::time::Duration::from_secs(15);

/// Run the exchange. `Ok(())` means the server admitted us and the sequence
/// carries on at the MCS Connect Initial.
///
/// # Errors
///
/// [`RdpError::AuthFailed`] when the server named a result code, which is a
/// statement about the redirected credentials and not about anything the
/// user typed. [`RdpError::Timeout`] against [`ConnectStage::Rdstls`], and
/// the decode errors of `rdp_pdu::rdstls`.
pub async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    framer: &mut Framer<S>,
    creds: &RdstlsCredentials,
) -> Result<()> {
    let frame = with_timeout(
        ConnectStage::Rdstls,
        RDSTLS_STEP,
        framer.read_expect(Expect::Exact(RdstlsCapabilities::LEN)),
    )
    .await?;
    let capabilities = RdstlsCapabilities::decode(&mut Reader::new(&frame))?;
    if !capabilities.supports_version_1() {
        // Version 1 is the only version MS-RDPBCGR 2.2.17 defines, so a
        // server that supports none of it is one we cannot talk to at all.
        // Saying so here beats sending a request it will not read.
        return Err(RdpError::Protocol(format!(
            "the server offered RDSTLS versions {:#06x}, which does not include version 1 \
             (MS-RDPBCGR 2.2.17.1)",
            capabilities.supported_versions
        )));
    }

    let request = RdstlsAuthRequest {
        redirection_guid: &creds.redirection_guid,
        username: &creds.username,
        domain: &creds.domain,
        password: &creds.password,
    };
    let mut bytes = Vec::with_capacity(request.size());
    request.encode_checked(&mut Writer::new(&mut bytes))?;
    tracing::debug!(
        stage = %ConnectStage::Rdstls,
        ?creds,
        "presenting the redirected credentials"
    );
    framer.write_pdu(&bytes).await?;

    let frame = with_timeout(
        ConnectStage::Rdstls,
        RDSTLS_STEP,
        framer.read_expect(Expect::Exact(RdstlsAuthResponse::LEN)),
    )
    .await?;
    let response = RdstlsAuthResponse::decode(&mut Reader::new(&frame))?;
    if !response.is_success() {
        tracing::info!(
            result_code = format_args!("{:#010x}", response.result_code),
            "the server refused the redirected credentials"
        );
        return Err(RdpError::AuthFailed(response.describe().to_owned()));
    }

    tracing::info!("rdstls authentication succeeded");
    Ok(())
}
