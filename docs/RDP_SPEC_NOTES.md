# RDP specification notes

The RDP stack in this workspace is written from the published Microsoft Open
Specifications rather than from anyone else's implementation. Writing it that
way surfaces two kinds of problem worth recording in one place: places where our
own design documents turned out to be wrong, and places where the code makes a
reading that only a specification vector can settle.

Everything here was found by implementing against the documents. Each entry says
what was believed, what is true, and how we know.

## 1. Open, and settled only by a vector

These are the places where the code had to choose between readings and the
evidence is inference rather than a published example. They are listed in the
order I would spend an afternoon on them.

### 1.1 The ZGFX token table is a reconstruction

`crates/rdp-codecs/src/zgfx.rs`, `TOKENS`.

MS-RDPBCGR 3.1.8.4.2.2.1 was not available when the decoder was written, so the
table was reconstructed. The eleven match rows carry their own proof: each
distance base is the previous base plus two to the power of the previous bit
count, eleven times in a row with no slack, and a test checks the chain. The
literal rows carry no such structure. If one literal row is wrong, EGFX traffic
gets a wrong byte every few thousand and surfaces as an occasional malformed
PDU, which is a miserable thing to chase.

This is the highest risk item in the RDP tree. One test against the MS-RDPBCGR
section 4 vector settles it.

**It is now live.** `rdp-core`'s graphics channel decompresses through it, so
this table is on the path of every EGFX frame. The earlier note here said it
must not go live before the vector is run; that was overtaken by wiring EGFX up,
and the decision was taken knowingly, because EGFX is worthless without it.

What was put in place instead of waiting. A wrong literal row produces bytes
that are wrong but structurally plausible, and the layer above catches that: an
`RDPGFX_HEADER` whose `pduLength` does not agree with what was decompressed is
an error naming ZGFX, this file and `zgfx.rs`, rather than a frame drawn from
mangled pixels. Two tests hold it, a unit one in `channels/egfx/tests.rs` and
`a_malformed_egfx_message_after_decompression_is_reported_and_names_zgfx` over a
real socket. So the failure mode is a named refusal, not silent corruption.

That is a guard, not a fix. A wrong row that happens to keep the header
consistent still corrupts pixels quietly. The MS-RDPBCGR section 4 vector is
still the thing that settles it, and it is still the first item to spend an
afternoon on.

### 1.2 The RemoteFX inverse DWT: two readings, one right

`crates/rdp-codecs/src/remotefx/dwt.rs`.

`PRDRDP/04 §4.6.5` states the unmodified JPEG 2000 5/3 inverse. But
`CLW_XFORM_DWT_53_A` halves its high pass on the forward transform, so the
inverse has to double it. The two forms are the same function only if the high
pass is read at two different scales, so exactly one is correct. The code takes
the doubled form.

The failure mode is what makes this worth listing: choosing wrong does not
corrupt the picture, it renders high frequency detail at half or double
amplitude. That survives review, and it survives a round trip against our own
encoder, because our encoder would have the same error. Only the MS-RDPRFX
section 4 vector distinguishes them.

### 1.3 ClearCodec RLEX segment split

`crates/rdp-codecs/src/clear.rs`, `rlex_code`.

Implemented as seven bits of stop index and one bit of suite depth, forced only
by `paletteCount <= 127`. A one bit suite depth is implausibly small for a field
the specification bothers to name, so this is the reading most likely to be
wrong.

### 1.4 SETTLED: `updateType` is on the wire in both paths

`crates/rdp-pdu/src/update/slowpath.rs`.

`PRDRDP/13 §5.6.1` says the field is repeated inside the body. `PRDRDP/04 §2.1`
says the slow path and fast path bodies are the same bytes, and lists no such
field. One of those puts two extra bytes on every slow path bitmap update.

The code followed `04` and it was wrong, which a capture has now settled.

A Windows 11 host (DESKTOP-H21K47C, 2026-08-24) begins its first fast path
bitmap update `01 00 a2 00`: `UPDATETYPE_BITMAP`, then 162 rectangles. The
argument for `04` was that the fast path update codes `0x0` to `0x3` are
numerically identical to the slow path `updateType` values, so the field only
looked doubled. The identity is real and the field is on the wire anyway.
MS-RDPBCGR 2.2.9.1.2.1.1 to 2.2.9.1.2.1.3 say why: the fast path body is the
slow path structure minus its *share data header*, and `updateType` was never
part of that header.

Reading it without the field made the first rectangle `destLeft = 162,
destRight = 0`, which is inverted, so every session died on its first tile with
a message about a malformed bitmap. The decoder, the encoder, the size
calculation and the mock server all now carry the field, and the real twelve
octet prefix is a test vector in `crates/rdp-pdu/src/update/fastpath.rs`.

Worth keeping as a lesson rather than only a fix: the mock server omitted the
field too, so 2,000 tests agreed with the decoder about bytes no server sends.
That is the failure mode section 1 of this file exists to name, and it took one
real connection to find four more of them.

### 1.5 Server Redirection field order, and where the packet starts

`crates/rdp-pdu/src/rdp/redirection.rs`.

Two separate uncertainties in one structure, both of which produce garbage
rather than an error if they are wrong.

`PRDRDP/13 §4.10.4` lists the tail of `RDP_SERVER_REDIRECTION_PACKET` as
`TsvUrl`, `RedirectionGuid`, `TargetCertificate`, `TargetNetAddresses`, putting
the address list last. Every other field in that structure runs in ascending
`RedirFlags` order, and `LB_TARGET_NET_ADDRESSES` is `0x800`, below
`LB_CLIENT_TSV_URL` at `0x1000` and well below the two flags appended later,
`LB_REDIRECTION_GUID` at `0x8000` and `LB_TARGET_CERTIFICATE` at `0x10000`. The
code puts `TargetNetAddresses` directly after `TsvUrl`. The two readings differ
only for a server that sets `LB_TARGET_NET_ADDRESSES` together with one of the
two later flags.

Separately, where the packet begins inside its two wrappers is a guess.
MS-RDPBCGR 2.2.13.2 puts a `pad2Octets` between the Share Control header and the
packet, which `read_standard` skips; 2.2.13.3 appears to put the packet
immediately after the four byte security header, which the plain `Decode`
assumes. `Flags` is a checked magic value precisely so that a wrong guess fails
as one `InvalidField` at offset zero or two, rather than assembling a host name
out of the middle of a password.

A captured broker redirection settles both.

### 1.6 Nothing declines RemoteFX Progressive, and now we decode it

`crates/rdp-codecs/src/progressive/`, `crates/rdp-core/src/channels/egfx/`.

This was the highest live interop risk in the tree and it is closed. The
decoder half: `rdp_codecs::progressive` is a decoder now, compiled by default,
and the entry the earlier version of this section carried, that it was a stub
behind an off by default feature, is gone.

The reasoning for the feature gate, recorded because the gate still exists.
Progressive is available from EGFX capability version 8, which is what we
advertise. There is no capability bit that says "do not send it":
`RDPGFX_CAPS_FLAG_AVC_DISABLED` exists only from version 10, and there is no
progressive equivalent at any version. So a server may legitimately send
`RDPGFX_CODECID_CAPROGRESSIVE` at any time, and a feature that is off cannot
save a session. It costs 17.9 KiB in a linked, LTO'd release binary that calls
both RemoteFX entry points, measured, which is 4.5 percent, and one more fuzz
target out of ten. `--no-default-features` still turns it off.

**The routing half is closed too.** `crates/rdp-core/src/channels/egfx/decode.rs`
sends codec id `0x0009` to `progressive::decode_message`, and the
`ProgressiveState` it hands over is a field of `Surface`, so it is created with
the surface, dropped with it, and refit when the geometry moves. The scratch is
RemoteFX's, shared because `progressive::scratch_len` is
`remotefx::scratch_len` and neither holds anything between calls.
`rdp_pdu::vc::egfx::codec_id` still does not define `0x0009`, so `rdp-core`
names it locally with a citation (`decode::CAPROGRESSIVE`); that constant
belongs in `rdp-pdu`.

What is not implemented is §4.9.4's cross context eviction, and it is a
deliberate omission rather than a gap. The per surface store is bounded by that
surface's own tile grid, `ceil(w/64) * ceil(h/64) * 24 KiB`, which is 47.8 MiB
at 4K; across the session it is bounded at one and a half times
`MAX_SURFACE_BYTES`, because a tile costs 24 KiB of coefficients for 16 KiB of
pixels. There is nothing an eviction could free that the surface budget has not
already refused.

`PRDRDP/04 §4.9` says progressive rides `WIRE_TO_SURFACE_2`, on the grounds
that it is the one codec with persistent state and that PDU is the one
carrying a `codecContextId`. That is the reading to be careful with when the
routing is written. `RDPGFX_WIRE_TO_SURFACE_PDU_2` carries no destination
rectangle at all, and a progressive region's tiles are placed by tile index
against a surface origin, so a decoder handed only a context id has nowhere to
put them. The decoder here takes a `DstView` and tile indices, which is what
`WIRE_TO_SURFACE_1` provides. If a real server turns out to use
`WIRE_TO_SURFACE_2` for `0x0009`, the codec does not change but the caller has
to synthesise the rectangle from the surface. A capture settles it.

### 1.6.1 The progressive wavelet has the same two readings as §1.2, plus a third question

`crates/rdp-codecs/src/progressive/dwt.rs`.

Progressive with `RFX_DWT_REDUCE_EXTRAPOLATE` clear runs
`remotefx::dwt::inverse_2d` itself, so it inherits §1.2 exactly: if the
doubled high pass is wrong there it is wrong here, by the same factor, and a
test asserts the two kernels are the same function so it stays one edit.

With the flag set, which is what Windows sends, there is a second question of
the same shape. The halves are 33 and 31 rather than 32 and 32, and the
missing high pass coefficient has to be supplied by the decoder. The module
takes the extrapolation to be linear, `X[64] = 2*X[63] - X[62]`, which makes
that coefficient identically zero for every input and is therefore the only
extension under which dropping it loses nothing. The band sizes that follow
are the only ones that sum to 4096, three sums with no slack, and a test
carries the arithmetic. It is still a reconstruction rather than a
transcription. MS-RDPEGFX 4.1.2 settles it, and `PRDRDP/09 §2.4.1` warns that
that example is small, so a capture from an xrdp 0.10 GFX session is the second
source and the one likely to arrive first.

The failure mode is the §1.2 one: choosing wrong does not corrupt the picture,
it renders one row and one column of every tile at the wrong amplitude, which
tiles the frame into a faint 64 pixel grid.

### 1.6.2 The SRL value width is derived, not transcribed

`crates/rdp-codecs/src/progressive/srl.rs`.

An upgrade pass codes a coefficient that becomes non zero as a sign bit and
`numBits` magnitude bits, where `numBits` is the difference between the two
bit positions. That width is forced: a coefficient insignificant at the old
position has a magnitude below `2^numBits` at the new one and at least one, so
`numBits` bits hold every legal value and no fewer do. The competing reading,
that the leading one is implied and only `numBits - 1` bits are sent, cannot
represent a magnitude of one at `numBits` of three, so it is ruled out.

What is **not** forced and is a straight guess is the order: sign first, then
magnitude, and the run coder's terminating value read after its remainder
bits. It is written that way because RLGR1's run mode does it that way and SRL
is RLGR1's run mode with a different terminating symbol. A wrong order does
not fail cleanly. It desynchronises the SRL stream from its first non zero
coefficient onward and the tile refines into noise, so it would look like a
wavelet bug rather than a bitstream one.

The three tile block headers are the other guess in the same file's
neighbourhood: 22 bytes for `WBT_TILE_SIMPLE`, 23 for `WBT_TILE_FIRST` with
its `quality` byte, and 26 for `WBT_TILE_UPGRADE` with six lengths and no
`flags`. That one does fail cleanly, which is why it is listed second: the
declared blob lengths are taken out of the block before anything is decoded,
so a header that is the wrong size makes almost every real tile a truncation
error naming the tile body rather than a wrong picture.

MS-RDPEGFX 4.1.2 is the vector for both, and `PRDRDP/09 §2.4.1` says that
example is small. The practical second source is a capture from an xrdp 0.10
GFX session, which is the only easily available live progressive traffic;
`PRDRDP/09 §2.4.1` already asks for that capture to be taken in phase 2, so it
may arrive before the document does.

### 1.7 Golden vectors we could not source

`PRDRDP/09 §9.2` calls for vectors transcribed from the annotated captures in
the MS-RDPBCGR section 4 material, which is not in the design set. Every vector
in the tree that is hand computed from a published field table says so in its
comment and shows the arithmetic. None of them is presented as a transcription.
They should be replaced when the documents are in hand.

### 1.8 SETTLED: the planar colour loss shift, and the width it happens in

`crates/rdp-codecs/src/planar.rs`, `crates/rdp-codecs/src/nscodec.rs`.

`PRDRDP/04 §4.5.5` gives the reconstruction as a left shift of Co and Cg by the
colour loss level and records the amount as ambiguous, `cll` or `cll - 1`,
asking for a vector to settle it. It leaves the width of the arithmetic
unstated as well. Both were got wrong, in two separate releases, and each
mistake produced a picture that looked almost right.

A Windows 11 host (DESKTOP-H21K47C, 2026-08-25) sends every 32 bpp tile with
`FormatHeader` `0x33`: `cll = 3`, no chroma subsampling, run length coded, no
alpha.

**The width.** The encoder's arithmetic right shift leaves `8 - cll`
meaningful bits in the stored byte and whatever it pushed above them.
Reconstruction has to happen in the same eight bits so that leftover falls off
the top, and the result is read as signed only then. Widening to `i16` first
keeps it and scales it as though it were signal: a stored `0x3B` reads as +472,
which no 8 bit RGB pixel can produce. Fixed in 0.13.2.

**The amount.** It is `cll - 1`, not `cll`, and the non lifting form
`T = Y - Cg; R = T - Co; G = Y + Cg; B = T + Co` goes with it. The lifting form
carries two halvings of its own and would need `cll`; the two are the same
transform written at different chroma scales. 0.13.2 shipped the lifting form
at `cll`, which is self consistent and still wrong, because the eight bit
reconstruction it now shared cannot hold a value twice as large: every sample
in the top half of its range overflowed and wrapped, flipping its sign. Fixed
in 0.13.4.

**What settles it, without a vector.** A correct scale never discards a set
bit, because the encoder can only emit what its own quantization produced. That
is measurable on a live session and needs no reference picture:

| reading | chroma bytes losing a set bit |
| --- | --- |
| widen to `i16`, shift `cll` | clamped instead: 1125 of 1921 tiles |
| eight bit, shift `cll` (0.13.3) | 2,474,934 of 15,745,024 (15.72%) |
| eight bit, shift `cll - 1` | 0 of 15,728,640 |

The failure mode is worth recording because it is not the one the clamp test
catches. A wrap does not leave `0..=255`, so nothing clamps and the earlier
check passed: 0.13.3 reported zero clamped tiles while 15.72% of its chroma was
sign flipped. It showed as hard edged patches of roughly the complementary hue
in the most saturated parts of the image, and nowhere else, because only large
samples overflow.

`the_shift_never_discards_a_bit_the_encoder_could_have_set` pins the invariant
without a server.

**Cross checked against FreeRDP**, which is the only independent implementation
to hand and interoperates with Windows: `libfreerdp/primitives/prim_YCoCg.c`
casts to `INT8` after the shift (`(INT16)((INT8)(raw << cll))`) and computes
`cll` as `shift - 1` where `libfreerdp/codec/planar.c` passes the level itself.
`libfreerdp/codec/nsc.c` does the same with `ColorLossLevel - 1`.

**NSCodec differs in one thing only**, and it is not the scale. Its
`ColorLossLevel` runs from 1 with 1 meaning no loss, so its shift is also
`field - 1`; the two definitions meet at the same arithmetic. But its Co has
the opposite sign, `R = Y + Co - Cg` against planar's `R = Y - Cg - Co`. This
tree negates at the NSCodec call site and shares the rest. Still not verified
against a real NSCodec server, only against this crate's own encoder, which is
exactly the weakness that hid both planar faults: our encoder made the same
assumption as our decoder, so the round trip agreed with itself at every colour
loss level while the picture was wrong.

### 1.9 SETTLED: Windows discards a `cliprdr` PDU without `CHANNEL_FLAG_SHOW_PROTOCOL`

`crates/rdp-core/src/channels/cliprdr.rs`, `send_header`.
`crates/rdp-pdu/src/vc/static_vc.rs`, `channel_flags::SHOW_PROTOCOL`.

**What was believed.** `CHANNEL_FLAG_SHOW_PROTOCOL` (`0x00000010` in
`CHANNEL_PDU_HEADER.flags`, MS-RDPBCGR 2.2.6.1.1) only decides whether the
channel PDU header is handed to the application endpoint or stripped before it
gets there. This crate parses the header either way, so the constant carried a
comment calling it "tolerated and ignored", and every outbound static channel
PDU went out with `FIRST|LAST` and nothing else.

**What is true.** That reading holds for what we receive and is wrong for what
we send. A Windows 11 host completes the whole clipboard handshake regardless:
it joins the channel, sends `CB_CLIP_CAPS` and then `CB_MONITOR_READY`. It then
discards every `cliprdr` PDU whose header does not set the flag, without an
error and without closing the channel. No `CB_FORMAT_LIST_RESPONSE` comes back,
the server never announces its own formats, so neither direction of copy and
paste works. `drdynvc` is unaffected on the same transport, which is what makes
the failure look like a clipboard bug rather than a channel one.

**How we know.** Against one Windows 11 host, with a `CB_FORMAT_LIST`
byte identical in both runs (`02000000 06000000 0d000000 0000`, announcing
`CF_UNICODETEXT` with an empty long name) on the correct channel, the only
variable was the header flags. With `0x00000003` the server sent nothing on
`cliprdr` after `CB_MONITOR_READY` for the life of the session. With
`0x00000013` it answered `CB_FORMAT_LIST_RESPONSE` within 18 ms, then announced
its own five formats on the next copy, and both directions worked. FreeRDP was
the control: it moved the clipboard on the same host in the same session, and
`freerdp_channel_send` sets this flag for any channel declared with
`CHANNEL_OPTION_SHOW_PROTOCOL`, which `cliprdr` is for FreeRDP and for mstsc.

**Not to be confused with** `CHANNEL_OPTION_SHOW_PROTOCOL` (`0x00200000` in
`CHANNEL_DEF.options`, MS-RDPBCGR 2.2.1.3.4.1), which is a different field in a
different structure, sent once at connect time rather than on every PDU.
Declaring that one was tried against the same host and changed nothing, which
is what 2.2.1.3.4.1 predicts when it says the server ignores it. The names are
close enough that `connection/mcs.rs` carries a comment pointing here.

`every_cliprdr_frame_shows_the_protocol` asserts the flag on real encoded
frames, because a reader who trusts the old comment would otherwise delete it
and break copy and paste against Windows with no test to say so.

### 1.10 SETTLED: gnome-remote-desktop waits for an answer to 2.2.14

`crates/rdp-core/src/connection/activate.rs`, `autodetect_step`.

**What was believed.** Network characteristics detection is optional and best
effort, so a client that never answers costs itself nothing: the server falls
back to its own connection type hint and carries on. The code said so and
logged the phase instead of answering it.

**What is true.** That holds for Windows and not for gnome-remote-desktop,
which sends the RTT request and the bandwidth start, payload and stop, and
then stops. No Demand Active follows. The connection dies after the Client
Info PDU with nothing on the wire to explain it, and the client's own timeout
is the only thing that ends the wait.

**How we know.** Against gnome-remote-desktop on Fedora, the sequence ran to
`CB_MONITOR_READY` equivalent and then produced exactly two auto detect PDUs
and silence. Answering them took the same connection to `licensing complete`
and a Demand Active. Windows was unaffected either way, which is what makes
the old reading look correct for as long as Windows is the only server tried.

Two details of that server are worth recording because they are not what
MS-RDPBCGR 2.2.14 leads you to expect. It uses the **continuous** phase
request codes during the connect sequence, not the connect time ones, so a
client that switches on the phase rather than the measurement answers none of
them. And it sends the bandwidth triplet more than once before moving on.
`autodetect_step` keys on the measurement and ignores the phase for that
reason.

### 1.11 OPEN: the graphics pipeline is advertised nowhere, and enabling it fails

`crates/rdp-pdu/src/gcc/client.rs`, `early_capability_flags::SUPPORT_DYNVC_GFX_PROTOCOL`.
`crates/rdp-core/src/channels/egfx/`.

**What was believed.** Section 1.1 of this document says of the ZGFX token
table that it "is now live", because "rdp-core's graphics channel decompresses
through it, so this table is on the path of every EGFX frame".

**What is true.** It is on no path at all.
`RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL` is defined and never set, in any crate.
Without it in `TS_UD_CS_CORE.earlyCapabilityFlags` no server offers
`Microsoft::Windows::RDS::Graphics`, so `channels::egfx` has never run against
a server. Windows degrades silently to the legacy bitmap path, which is why
nothing ever looked wrong.

**How we know.** No Windows session in any trace was offered the graphics
channel. Setting the flag made both servers offer or demand it, and both then
failed:

* Windows opens the channel and ends the session on our `RDPGFX_CAPS_ADVERTISE`
  with `ERRINFO_GRAPHICSSUBSYSTEMFAILED` (0x0000112f). The advertisement is
  two capability sets, `V8` and `V8_1`, with no flags.
* gnome-remote-desktop requires the flag to proceed at all, logging "Client
  did not advertise support for the Graphics Pipeline, closing connection" and
  hanging up after licensing without it. With it, the connection completes to
  `font map received`, negotiates `drdynvc` version 1, and then never creates
  the graphics channel. Since that server paints only through EGFX, the result
  is a connected session showing a black screen.

So the flag is a switch rather than a default. `mcs::GFX_ENV`
(`DESKVNC_RDP_GRAPHICS_PIPELINE=1`) sets it, and nothing else does, so
testing one of these two servers cannot break the other. Shipping it on
traded a working Windows session for a GNOME one, which is a trade nobody
asked for.

**The GNOME half of this entry is closed.** That server was not waiting on
the graphics channel at all (section 1.12), and once the four faults of
sections 1.12 to 1.17 were fixed a gnome-remote-desktop session paints,
resizes and carries a clipboard. What was left after the flag was: a
handover redirection this client refused, a routing token it double encoded,
an RDSTLS exchange it did not speak, a `WIRE_TO_SURFACE_2` it refused
outright, an EGFX reply it wrapped in an envelope no server expects, and a
`bitmapDataLength` it did not read. None of those was the flag.

**The Windows half is still open and is now untested rather than known
broken.** That host ended the session with `ERRINFO_GRAPHICSSUBSYSTEMFAILED`
on an `RDPGFX_CAPS_ADVERTISE` that carried a segment envelope it should not
have had (section 1.15). No Windows host has been tried since that was
fixed, so the failure may already be gone. Until one is, this stays open:
closing it on the reasoning alone is how the advertisement got shipped on by
default the first time.

### 1.12 SETTLED: gnome-remote-desktop hands the session over by redirecting to itself

`crates/rdp-core/src/session/redirect.rs`, `Redirection::from_packet`.

**What was believed.** Section 1.11 read the GNOME black screen as a graphics
failure: the connection completed, `drdynvc` negotiated, no graphics channel
appeared, and the server paints only through EGFX.

**What is true.** The graphics channel never appeared because the connection
we were watching had already been superseded. gnome-remote-desktop 50 runs
its system daemon and the user's session as separate RDP servers and moves a
client between them with a Server Redirection PDU (MS-RDPBCGR 2.2.13.1). That
redirection names **no target**: the client returns to the same host and the
same port, and the daemon tells the returning connection apart from a fresh
one by peeking the `Cookie: msts=` routing token on the X.224 Connection
Request. Our `from_packet` required a target and refused the whole packet, so
we never reconnected, and the daemon eventually gave up on a client that was
still sitting on the old socket.

**How we know.** The server's journal, from the window in which the graphics
flag was set:

```
[RDP] Sending server redirection
[DaemonSystem] Aborting handover, removing remote client with remote id ...
ERRINFO_CB_CONNECTION_CANCELLED [0x00010409]
```

and, in the daemon binary, `Cookie: msts=`, `RoutingToken: Aborting current
peek operation (Timeout reached)`, `utf16_encoded_redirection_guid` and
`org.gnome.RemoteDesktop.Rdp.Handover`.

A redirection is now refused only when it names neither a host to dial nor a
token to present, which is the one case where the next attempt would be byte
for byte the one that just failed. `MAX_CHAINED_REATTEMPTS` bounds a handover
chain at eight either way.

What this does not settle is the Windows half of 1.11, which is a real
`RDPGFX_CAPS_ADVERTISE` rejection and unrelated to any of this.

### 1.13 SETTLED: `LoadBalanceInfo` is the whole routing token, not the part after `msts=`

`crates/rdp-pdu/src/x224.rs`, `X224Cookie::RoutingToken`.

**What was believed.** That `X224Cookie::RoutingToken` holds the opaque token
that follows `Cookie: msts=`, so the encoder owns both the prefix and the
CRLF. A token arriving with a terminator of its own was treated as malformed
and refused before a byte was written.

**What is true.** The `LoadBalanceInfo` field of a Server Redirection
(MS-RDPBCGR 2.2.13.1) is the routing token in full: prefix, value and CRLF.
Prepending a second `Cookie: msts=` and appending a second CRLF produces a
Connection Request no server can read. MS-RDPBCGR 3.2.5.3.1 says only that
the client "sends the routing token", which is why this was readable either
way until a server actually sent one.

**How we know.** gnome-remote-desktop's handover cookie is 24 bytes and ends
in CRLF, so the first reconnection after §1.12 died in our own encoder with
"routing token contains its own terminator". FreeRDP settles the reading:
`nego_send_negotiation_request` writes `RoutingToken` verbatim and appends a
CRLF only when one is not already there.

`encode` now decides by looking at the bytes, so both shapes work: a bare
token still gets the prefix and the terminator, and a complete field is
written through untouched. `check` still refuses a CRLF anywhere other than
the end, which is the case that would split the field on the wire.

### 1.14 OPEN: gnome-remote-desktop finishes its handover with RDSTLS

`crates/rdp-core/src/connection/negotiate.rs`, `REQUESTED_PROTOCOLS`.

**What was believed.** Briefly, and wrongly, that
`LB_PASSWORD_IS_PK_ENCRYPTED` without `LB_TARGET_CERTIFICATE` would mean the
handover password is a plain UTF-16 string. gnome-remote-desktop sends both,
so the guess never applied and was backed out.

**What is true.** The redirection is a complete RDSTLS authentication input
and nothing else will do. The observed packet:

```
redir_options=0x00004000 session_id=0
target_net_address=false target_fqdn=false target_netbios_name=false
load_balance_info=25 username=true domain=false
password=34 password_is_pk_encrypted=true
redirection_guid=true target_certificate=true
```

`RedirectionGuid`, `UserName`, `Domain` and a `Password` encrypted under the
public key of `TargetCertificate` are exactly the fields of an RDSTLS
Authentication Request PDU (MS-RDPBCGR 2.2.17.1). A client never decrypts
that password; it forwards the blob over the TLS channel and the target
decrypts it with the private half. NLA has nowhere to put it, which is why
our reconnection falls back to prompting and the user's own password is
rejected by a daemon that was never told it.

**How we know.** The daemon says so to the user: "This Remote Desktop
connection is insecure. To secure this connection, enable RDSTLS Security in
your client". `negotiate.rs` is equally clear in the other direction, listing
`RDSTLS` and `RDSAAD` among the protocols "we did not" implement, and
`REQUESTED_PROTOCOLS` offers only `SSL | HYBRID`.

**What was built.** `crates/rdp-pdu/src/rdstls.rs` for the three structures
and `crates/rdp-core/src/connection/rdstls.rs` for the exchange.
`PROTOCOL_RDSTLS` is offered only when a redirection supplied credentials
(`negotiate::requested_protocols`) and accepted only when it was offered,
because a client that asks for this protocol without a redirection behind it
has nothing to send when the server obliges. `Redirection` now keeps the
redirection GUID and the ciphertext instead of dropping them.

**What is still open.** Two details of 2.2.17 are inferred rather than read
off a wire, and the first run against gnome-remote-desktop is what settles
them:

* That these PDUs carry no TPKT header and no length prefix, so each read is
  an `Expect::Exact` of a fixed size. Every structure except the
  authentication request is fixed length, and the client only writes that
  one.
* That the server speaks first with the capabilities PDU. If it waits for us
  instead, the exchange times out against `ConnectStage::Rdstls` rather than
  failing in a way that needs interpreting.

`RDSTLS_DATA_CAPABILITIES`, `RDSTLS_DATA_PASSWORD_CREDS` and
`RDSTLS_DATA_RESULT_CODE` are all 0x0001: the field distinguishes bodies
within a `PduType`, not across them.

### 1.15 SETTLED: `RDP_SEGMENTED_DATA` frames the server to client direction only

`crates/rdp-core/src/channels/dvc.rs`, `DvcMux::flush`.

**What was believed.** That every EGFX message rides in an
`RDP_SEGMENTED_DATA` envelope (MS-RDPEGFX 2.2.5.1) whichever way it is
going, with a client's marked literal: descriptor `SINGLE`, then a flags
byte of `PACKET_COMPR_TYPE_RDP8` with `PACKET_COMPRESSED` clear.

**What is true.** That envelope frames the server to client graphics stream
and only that direction. A client sends its capability advertisement, its
cache import offer and its frame acknowledgements as bare `RDPGFX_HEADER`
PDUs. A server that receives one with the envelope on it reads the segment
descriptor as the command id and the two bytes after it as `flags`, which
puts `pduLength` two bytes off the end of where it belongs.

**How we know.** The arithmetic, from gnome-remote-desktop's journal:

```
[rdpgfx_read_header] invalid length, got 28, require at least 2228216
```

Our advertisement went out as `E0 04 | 12 00 | 00 00 | 22 00 00 00 ...`,
36 bytes. Read from offset zero that is cmdId 0x04E0, flags 0x0012 and
`pduLength` 0x00220000, which is 2228224; FreeRDP then wants
`pduLength - 8` more bytes, which is 2228216 exactly, and has 36 - 8 = 28,
which is the other number in the line. Both match to the byte, so this is
not an inference.

Ten seconds later the server gave up:

```
[RDP.RDPGFX] Client did not respond to protocol initiation. Terminating session
ERRINFO_BAD_CAPABILITIES (0x000010EA)
```

This is very likely the whole of the Windows half of section 1.11 as well.
That host opened the graphics channel and ended the session with
`ERRINFO_GRAPHICSSUBSYSTEMFAILED` on the same malformed advertisement, and
no Windows host has been tried since the framing was corrected. Section 1.11
should not be closed on that guess until one has been.

The mock server in `crates/rdp-core/tests/common/` stripped the envelope,
which is how a client that sent one passed every test in the tree and was
refused by the first real server it met. It now refuses the envelope the way
FreeRDP does.

### 1.16 SETTLED: the progressive codec draws through `WIRE_TO_SURFACE_2`

`crates/rdp-core/src/channels/egfx/mod.rs`, the `WireToSurface2` arm.

**What was believed.** That `RDPGFX_WIRE_TO_SURFACE_PDU_2`
(MS-RDPEGFX 2.2.2.2) needs "a persistent codec context this client never
created", so any server sending one was drawing with something it had not
been offered. The arm was a refusal.

**What is true.** The persistent codec context is the surface's progressive
tile store, which this client has had all along and for exactly this reason:
a first pass leaves a coarse tile behind and a later `WBT_TILE_UPGRADE`
refines that same tile in place, so the store outlives the message and dies
with the surface (`surface::Surface::progressive`, MS-RDPEGFX 2.2.4.2).

The only real difference from `_1` is that `_2` names no destination
rectangle. It does not need one: an `RFX_PROGRESSIVE_REGION` carries the
coordinates of every tile inside the stream, so the destination is the whole
surface.

**How we know.** gnome-remote-desktop confirmed capability set 8.1, reset the
pipeline at 1280x726, created surface 0, mapped it to the output, and sent a
27 KiB frame in codec 0x0009. Every step of that is in the client log. The
frame was `WIRE_TO_SURFACE_2` and the refusal ended the session on the first
frame of pixels that had ever reached this client.

`RDPGFX_DELETE_ENCODING_CONTEXT` (2.2.2.3) now clears that store rather than
tracing that there was nothing to clear: a server that deletes a context will
not send the upgrades that would have refined what is in it, and refining a
tile the server believes it discarded is how one frame comes back carrying
another frame's coefficients.

### 1.17 SETTLED: `WIRE_TO_SURFACE_2` carries a `bitmapDataLength`

`crates/rdp-pdu/src/vc/egfx.rs`, the `WIRE_TO_SURFACE_2` body decoder.

**What was believed.** The type's own documentation said it: "No
`bitmapDataLength`: the payload runs to the end of the PDU as `pduLength`
declared it. That asymmetry with `_1` is why the dispatcher takes
`pduLength - 8` before calling a body decoder."

**What is true.** There is no asymmetry. `RDPGFX_WIRE_TO_SURFACE_PDU_2`
carries a `bitmapDataLength` between `pixelFormat` and `bitmapData`, exactly
as `_1` does. Reading the structure without it starts the codec bitstream
four bytes early, which puts every field of that bitstream four bytes out.

**How we know.** The arithmetic, to the byte. gnome-remote-desktop sent a
27366 byte `bitmapData`, and the progressive decoder refused its first block
as an unknown type with a `blockLen` of 3435134976, which is 0xCCC00000:

```
offset 0..2   E2 6A         read as blockType, unknown
offset 2..6   00 00 C0 CC   read as blockLen, 0xCCC00000
```

0xCCC0 is `WBT_SYNC`. It is sitting at offset 4, where a stream that began
after a four byte length field would put it. Those four bytes read as a
little endian `u32` are 0x00006AE2, which is 27362, which is 27366 - 4: the
length of everything after them. Both the position of the sync magic and the
value of the length agree, so this is not an inference.

Two independent facts confirm the first nine bytes were already right, so the
four are between `pixelFormat` and the bitstream rather than in front of the
structure: `surfaceId` decoded as 0, which is the surface the server had just
created, and `codecId` as 0x0009, which is a codec that exists.

The declared length is checked against what is left rather than trusted. The
four bytes are either a length or the first four bytes of a bitstream and
there is no reading of them that is right by accident, so a server that
disagrees produces a named error instead of a picture assembled from the
wrong offset. The test that pins this builds the bytes by hand: a round trip
would prove only that our encoder and decoder agree with each other, which
they did while both were wrong.
