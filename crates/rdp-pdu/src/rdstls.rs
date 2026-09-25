//! RDSTLS: the authentication exchange a redirected connection runs in place
//! of CredSSP (MS-RDPBCGR 2.2.17, 5.4.5.3).
//!
//! Three structures over one TLS channel, in a fixed order:
//!
//! ```text
//! server -> client   RDSTLS_CapabilitiesPDU     2.2.17.1
//! client -> server   RDSTLS_AuthReqPDU...       2.2.17.2
//! server -> client   RDSTLS_AuthRspPDU          2.2.17.3
//! ```
//!
//! # Why a client that cannot decrypt a password can still present one
//!
//! A Server Redirection whose `RedirFlags` carries
//! `LB_PASSWORD_IS_PK_ENCRYPTED` hands the client a `Password` encrypted
//! under the public key of `LB_TARGET_CERTIFICATE`. The client holds no half
//! of that key and never reads the field. It forwards the blob verbatim in
//! [`RdstlsAuthRequest::password`] and the target, which does hold the
//! private half, decrypts it. That is the whole reason this protocol exists
//! and the reason NLA cannot stand in for it: an NTLM exchange needs a
//! password it can compute over.
//!
//! # What is inferred rather than read off a wire
//!
//! These PDUs carry no TPKT header and no length prefix of their own: each
//! is either a fixed size or self describing through its own length fields,
//! and the TLS record boundary is the frame. Every structure here is a fixed
//! size except [`RdstlsAuthRequest`], which the client only writes, so a
//! reader never has to find the end of one it did not send.
//! `docs/RDP_SPEC_NOTES.md` §1.14 records this as inferred.

use crate::io::error::{PduError, PduResult};
use crate::io::{Decode, Encode, Reader, Writer};

/// `RDSTLS_VERSION_1`, the only version defined.
pub const VERSION_1: u16 = 0x0001;

/// The longest single field we will read out of one of these PDUs.
///
/// A redirection GUID is sixteen bytes, a user name and a domain are short,
/// and a password encrypted under a 4096 bit key is 512. Eight kilobytes is
/// far above all of them and far below anything that would hurt.
pub const MAX_RDSTLS_FIELD: usize = 8192;

/// `PduType`, the second field of every RDSTLS PDU.
pub mod pdu_type {
    /// `RDSTLS_TYPE_CAPABILITIES`.
    pub const CAPABILITIES: u16 = 0x0001;
    /// `RDSTLS_TYPE_AUTHREQ`.
    pub const AUTHREQ: u16 = 0x0002;
    /// `RDSTLS_TYPE_AUTHRSP`.
    pub const AUTHRSP: u16 = 0x0004;
}

/// `DataType`, which says which shape of body follows the header.
pub mod data_type {
    /// `RDSTLS_DATA_CAPABILITIES`, and `RDSTLS_DATA_PASSWORD_CREDS`, and
    /// `RDSTLS_DATA_RESULT_CODE`. The specification gives all three the same
    /// value: the field distinguishes bodies within a `PduType`, not across
    /// them, and each of those three is the first body of its own type.
    pub const CAPABILITIES: u16 = 0x0001;
    /// `RDSTLS_DATA_PASSWORD_CREDS`.
    pub const PASSWORD_CREDS: u16 = 0x0001;
    /// `RDSTLS_DATA_RESULT_CODE`.
    pub const RESULT_CODE: u16 = 0x0001;
    /// `RDSTLS_DATA_AUTORECONNECT_COOKIE`, the other shape of authentication
    /// request. We never send it: a redirection hands us a password, and an
    /// auto reconnect cookie belongs to a session this client is not
    /// resuming.
    pub const AUTORECONNECT_COOKIE: u16 = 0x0002;
}

/// `ResultCode` of the authentication response (MS-RDPBCGR 2.2.17.3).
pub mod result_code {
    /// The only value that means the exchange succeeded.
    pub const SUCCESS: u32 = 0x0000_0000;
    /// `RDSTLS_RESULT_ACCESS_DENIED`.
    pub const ACCESS_DENIED: u32 = 0x0000_0005;
    /// `RDSTLS_RESULT_LOGON_FAILURE`.
    pub const LOGON_FAILURE: u32 = 0x0000_052e;
    /// `RDSTLS_RESULT_INVALID_LOGON_HOURS`.
    pub const INVALID_LOGON_HOURS: u32 = 0x0000_0530;
    /// `RDSTLS_RESULT_PASSWORD_EXPIRED`.
    pub const PASSWORD_EXPIRED: u32 = 0x0000_0532;
    /// `RDSTLS_RESULT_ACCOUNT_DISABLED`.
    pub const ACCOUNT_DISABLED: u32 = 0x0000_0533;
    /// `RDSTLS_RESULT_PASSWORD_MUST_CHANGE`.
    pub const PASSWORD_MUST_CHANGE: u32 = 0x0000_0773;
    /// `RDSTLS_RESULT_ACCOUNT_LOCKED_OUT`.
    pub const ACCOUNT_LOCKED_OUT: u32 = 0x0000_0775;

    /// The sentence a failure shows the user.
    ///
    /// Every one of these is a logon outcome rather than a transport fault,
    /// so the text says what the account did, not what the socket did.
    #[must_use]
    pub const fn describe(code: u32) -> &'static str {
        match code {
            SUCCESS => "the server accepted the redirected credentials",
            ACCESS_DENIED => "the server refused the redirected credentials",
            LOGON_FAILURE => "the redirected credentials were not accepted",
            INVALID_LOGON_HOURS => "the account is not allowed to sign in at this time",
            PASSWORD_EXPIRED => "the account's password has expired",
            ACCOUNT_DISABLED => "the account is disabled",
            PASSWORD_MUST_CHANGE => "the account's password must be changed",
            ACCOUNT_LOCKED_OUT => "the account is locked out",
            _ => "the server refused the redirected credentials for an unnamed reason",
        }
    }
}

/// Read and check `Version` and `PduType`, which open every RDSTLS PDU.
fn read_header(r: &mut Reader<'_>, context: &'static str, expected: u16) -> PduResult<()> {
    let at = r.offset();
    let version = r.u16(context)?;
    if version != VERSION_1 {
        return Err(PduError::InvalidField {
            context,
            field: "Version",
            value: u64::from(version),
            offset: at,
        });
    }
    let at = r.offset();
    let pdu_type = r.u16(context)?;
    if pdu_type != expected {
        return Err(PduError::InvalidField {
            context,
            field: "PduType",
            value: u64::from(pdu_type),
            offset: at,
        });
    }
    Ok(())
}

/// Read and check `DataType`.
fn read_data_type(r: &mut Reader<'_>, context: &'static str, expected: u16) -> PduResult<()> {
    let at = r.offset();
    let data_type = r.u16(context)?;
    if data_type != expected {
        return Err(PduError::InvalidField {
            context,
            field: "DataType",
            value: u64::from(data_type),
            offset: at,
        });
    }
    Ok(())
}

/// `RDSTLS_CapabilitiesPDU` (MS-RDPBCGR 2.2.17.1), server to client.
///
/// Eight bytes that say the exchange has begun and which versions the server
/// will accept. We answer version 1 whatever it says, because version 1 is
/// the only version the specification defines; the field is read so that a
/// server offering something else is a named error rather than a silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdstlsCapabilities {
    /// `SupportedVersions`, a mask.
    pub supported_versions: u16,
}

impl RdstlsCapabilities {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDSTLS_CapabilitiesPDU";
    /// `Version`, `PduType`, `DataType`, `SupportedVersions`.
    pub const LEN: usize = 8;

    /// True when the server will accept the only version we speak.
    #[must_use]
    pub const fn supports_version_1(self) -> bool {
        self.supported_versions & VERSION_1 != 0
    }
}

impl Encode for RdstlsCapabilities {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(VERSION_1);
        w.u16(pdu_type::CAPABILITIES);
        w.u16(data_type::CAPABILITIES);
        w.u16(self.supported_versions);
        Ok(())
    }
}

impl<'a> Decode<'a> for RdstlsCapabilities {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        read_header(r, Self::NAME, pdu_type::CAPABILITIES)?;
        read_data_type(r, Self::NAME, data_type::CAPABILITIES)?;
        Ok(Self {
            supported_versions: r.u16(Self::NAME)?,
        })
    }
}

/// `RDSTLS_AuthReqPDUWithPasswordCredentials` (MS-RDPBCGR 2.2.17.2), client
/// to server.
///
/// Every field is a `u16` length followed by that many bytes. The three
/// strings are UTF-16LE with their terminator inside the length, which is the
/// form the Server Redirection already carried them in, so they are copied
/// rather than transcoded. The password is ciphertext and is never anything
/// else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdstlsAuthRequest<'a> {
    /// `RedirectionGuid`, verbatim from `LB_REDIRECTION_GUID`.
    pub redirection_guid: &'a [u8],
    /// `UserName`, UTF-16LE.
    pub username: &'a [u8],
    /// `Domain`, UTF-16LE. Empty is legal and is what a server that named no
    /// domain in the redirection gets back.
    pub domain: &'a [u8],
    /// `Password`, the blob from `LB_PASSWORD`, encrypted under the public
    /// key of `LB_TARGET_CERTIFICATE` and opaque here.
    pub password: &'a [u8],
}

impl RdstlsAuthRequest<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDSTLS_AuthReqPDUWithPasswordCredentials";

    /// Every field, in wire order.
    const fn fields(&self) -> [&[u8]; 4] {
        [
            self.redirection_guid,
            self.username,
            self.domain,
            self.password,
        ]
    }
}

/// Write a `u16` length and the bytes it counts.
fn write_field(w: &mut Writer<'_>, field: &[u8], context: &'static str) -> PduResult<()> {
    let Ok(len) = u16::try_from(field.len()) else {
        return Err(PduError::Encode {
            context,
            reason: "a field is longer than its u16 length can state",
        });
    };
    w.u16(len);
    w.bytes(field);
    Ok(())
}

/// Read a `u16` length and the bytes it counts, capped.
fn read_field<'a>(r: &mut Reader<'a>, context: &'static str) -> PduResult<&'a [u8]> {
    let at = r.offset();
    let len = usize::from(r.u16(context)?);
    if len > MAX_RDSTLS_FIELD {
        return Err(PduError::CapExceeded {
            context,
            declared: len,
            cap: MAX_RDSTLS_FIELD,
            limit_name: "MAX_RDSTLS_FIELD",
            offset: at,
        });
    }
    let mut body = r.take(len, context)?;
    Ok(body.rest())
}

impl Encode for RdstlsAuthRequest<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        // Version, PduType, DataType, then a u16 length on each field.
        6 + self.fields().iter().map(|f| 2 + f.len()).sum::<usize>()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(VERSION_1);
        w.u16(pdu_type::AUTHREQ);
        w.u16(data_type::PASSWORD_CREDS);
        for field in self.fields() {
            write_field(w, field, Self::NAME)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for RdstlsAuthRequest<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        read_header(r, Self::NAME, pdu_type::AUTHREQ)?;
        read_data_type(r, Self::NAME, data_type::PASSWORD_CREDS)?;
        Ok(Self {
            redirection_guid: read_field(r, Self::NAME)?,
            username: read_field(r, Self::NAME)?,
            domain: read_field(r, Self::NAME)?,
            password: read_field(r, Self::NAME)?,
        })
    }
}

/// `RDSTLS_AuthRspPDU` (MS-RDPBCGR 2.2.17.3), server to client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdstlsAuthResponse {
    /// `ResultCode`, one of [`result_code`].
    pub result_code: u32,
}

impl RdstlsAuthResponse {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDSTLS_AuthRspPDU";
    /// `Version`, `PduType`, `DataType`, `ResultCode`.
    pub const LEN: usize = 10;

    /// True when the server let us in.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.result_code == result_code::SUCCESS
    }

    /// The sentence a failure shows the user.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        result_code::describe(self.result_code)
    }
}

impl Encode for RdstlsAuthResponse {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(VERSION_1);
        w.u16(pdu_type::AUTHRSP);
        w.u16(data_type::RESULT_CODE);
        w.u32(self.result_code);
        Ok(())
    }
}

impl<'a> Decode<'a> for RdstlsAuthResponse {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        read_header(r, Self::NAME, pdu_type::AUTHRSP)?;
        read_data_type(r, Self::NAME, data_type::RESULT_CODE)?;
        Ok(Self {
            result_code: r.u32(Self::NAME)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut out = Vec::with_capacity(pdu.size());
        pdu.encode_checked(&mut Writer::new(&mut out))
            .expect("encodes");
        out
    }

    fn utf16(s: &str) -> Vec<u8> {
        let mut out: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.extend_from_slice(&[0, 0]);
        out
    }

    /// The capabilities PDU is eight bytes and every one of them is fixed
    /// except the last two.
    #[test]
    fn the_capabilities_pdu_is_eight_bytes_of_known_shape() {
        let pdu = RdstlsCapabilities {
            supported_versions: VERSION_1,
        };
        let bytes = encode(&pdu);
        assert_eq!(bytes, vec![0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00]);
        assert_eq!(bytes.len(), RdstlsCapabilities::LEN);
        assert_eq!(
            RdstlsCapabilities::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
        assert!(pdu.supports_version_1());
        assert!(!RdstlsCapabilities {
            supported_versions: 0
        }
        .supports_version_1());
    }

    /// The authentication request is the one structure this client writes,
    /// and the byte layout is the whole of it: a six byte header, then a
    /// `u16` length in front of each of four fields, in this order.
    #[test]
    fn the_authentication_request_lays_its_four_fields_out_in_order() {
        let guid = [0xaa; 16];
        let username = utf16("one-time");
        let domain: Vec<u8> = Vec::new();
        let password = [0xde, 0xad, 0xbe, 0xef];
        let pdu = RdstlsAuthRequest {
            redirection_guid: &guid,
            username: &username,
            domain: &domain,
            password: &password,
        };

        let bytes = encode(&pdu);
        let mut want = vec![0x01, 0x00, 0x02, 0x00, 0x01, 0x00];
        want.extend_from_slice(&16u16.to_le_bytes());
        want.extend_from_slice(&guid);
        want.extend_from_slice(&(username.len() as u16).to_le_bytes());
        want.extend_from_slice(&username);
        want.extend_from_slice(&0u16.to_le_bytes());
        want.extend_from_slice(&4u16.to_le_bytes());
        want.extend_from_slice(&password);
        assert_eq!(bytes, want);

        assert_eq!(
            RdstlsAuthRequest::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
    }

    /// Success is zero and nothing else is, and every named failure says
    /// something a user can act on.
    #[test]
    fn the_authentication_response_tells_success_from_every_failure() {
        let ok = RdstlsAuthResponse {
            result_code: result_code::SUCCESS,
        };
        let bytes = encode(&ok);
        assert_eq!(bytes.len(), RdstlsAuthResponse::LEN);
        assert_eq!(
            RdstlsAuthResponse::decode(&mut Reader::new(&bytes)).unwrap(),
            ok
        );
        assert!(ok.is_success());

        for code in [
            result_code::ACCESS_DENIED,
            result_code::LOGON_FAILURE,
            result_code::INVALID_LOGON_HOURS,
            result_code::PASSWORD_EXPIRED,
            result_code::ACCOUNT_DISABLED,
            result_code::PASSWORD_MUST_CHANGE,
            result_code::ACCOUNT_LOCKED_OUT,
            0xdead_beef,
        ] {
            let pdu = RdstlsAuthResponse { result_code: code };
            assert!(!pdu.is_success(), "{code:#x} read as success");
            let bytes = encode(&pdu);
            assert_eq!(
                RdstlsAuthResponse::decode(&mut Reader::new(&bytes)).unwrap(),
                pdu
            );
            assert!(!pdu.describe().is_empty());
        }
    }

    /// A PDU of the wrong type read as another is the mistake that turns one
    /// exchange into a stall, so each decoder checks all three head fields.
    #[test]
    fn a_pdu_of_the_wrong_type_or_version_is_refused() {
        let caps = encode(&RdstlsCapabilities {
            supported_versions: VERSION_1,
        });
        assert!(RdstlsAuthResponse::decode(&mut Reader::new(&caps)).is_err());

        let rsp = encode(&RdstlsAuthResponse { result_code: 0 });
        assert!(RdstlsCapabilities::decode(&mut Reader::new(&rsp)).is_err());

        let mut wrong_version = caps.clone();
        wrong_version[0] = 0x02;
        assert!(RdstlsCapabilities::decode(&mut Reader::new(&wrong_version)).is_err());

        let mut wrong_data_type = caps;
        wrong_data_type[4] = 0x09;
        assert!(RdstlsCapabilities::decode(&mut Reader::new(&wrong_data_type)).is_err());
    }

    /// A length field is the one place a server can ask for more than we
    /// have, and every short read has to be an error rather than a panic.
    #[test]
    fn every_prefix_of_every_pdu_errors_without_panicking() {
        let guid = [0xaa; 16];
        let username = utf16("one-time");
        let request = encode(&RdstlsAuthRequest {
            redirection_guid: &guid,
            username: &username,
            domain: &[],
            password: &[0xde, 0xad],
        });
        for cut in 0..request.len() {
            assert!(
                RdstlsAuthRequest::decode(&mut Reader::new(&request[..cut])).is_err(),
                "authentication request truncated to {cut} bytes decoded"
            );
        }

        let caps = encode(&RdstlsCapabilities {
            supported_versions: VERSION_1,
        });
        for cut in 0..caps.len() {
            assert!(RdstlsCapabilities::decode(&mut Reader::new(&caps[..cut])).is_err());
        }

        let rsp = encode(&RdstlsAuthResponse { result_code: 0 });
        for cut in 0..rsp.len() {
            assert!(RdstlsAuthResponse::decode(&mut Reader::new(&rsp[..cut])).is_err());
        }
    }

    /// A field length is a `u16`, so a hostile one cannot be enormous, but it
    /// can still be larger than anything real. The cap names itself.
    #[test]
    fn a_field_longer_than_the_cap_is_refused_by_name() {
        let mut bytes = vec![0x01, 0x00, 0x02, 0x00, 0x01, 0x00];
        bytes.extend_from_slice(&((MAX_RDSTLS_FIELD + 1) as u16).to_le_bytes());
        bytes.resize(bytes.len() + MAX_RDSTLS_FIELD + 1, 0);
        match RdstlsAuthRequest::decode(&mut Reader::new(&bytes)) {
            Err(PduError::CapExceeded { limit_name, .. }) => {
                assert_eq!(limit_name, "MAX_RDSTLS_FIELD");
            }
            other => panic!("expected a cap error, got {other:?}"),
        }
    }
}
