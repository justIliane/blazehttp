# BlazeHTTP HTTP/2 Conformance Report

## h2spec Results

**Tool:** h2spec v2.6.0
**Result:** 146/146 tests passed (100%)
**Date:** 2026-02-21

```
$ h2spec -h 127.0.0.1 -p 8443 -t --insecure
146 tests, 146 passed, 0 skipped, 0 failed
```

### Test Sections

| Section | Tests | Status |
|---------|-------|--------|
| 3. Starting HTTP/2 | 3 | PASS |
| 4. HTTP Frames | 4 | PASS |
| 5. Streams and Multiplexing | 16 | PASS |
| 6. Frame Definitions | 30 | PASS |
| 8. HTTP Message Exchanges | 8 | PASS |
| HPACK 2. Compression Process | 2 | PASS |
| HPACK 4. Dynamic Table Management | 1 | PASS |
| HPACK 5. Primitive Type Representations | 1 | PASS |
| HPACK 6. Binary Format | 1 | PASS |
| Generic tests | 80 | PASS |

## RFC 9113 Compliance

### Stream State Machine (Section 5.1)

- Idle, open, half-closed(local/remote), reserved, closed states implemented
- HEADERS on idle stream: opens new stream
- HEADERS on closed stream: GOAWAY STREAM_CLOSED
- HEADERS on half-closed(remote): RST_STREAM STREAM_CLOSED
- DATA on idle stream: GOAWAY PROTOCOL_ERROR
- DATA on closed stream: RST_STREAM STREAM_CLOSED
- RST_STREAM on idle stream: GOAWAY PROTOCOL_ERROR
- WINDOW_UPDATE on idle stream: GOAWAY PROTOCOL_ERROR
- Even stream IDs from client: GOAWAY PROTOCOL_ERROR
- Stream ID regression: GOAWAY STREAM_CLOSED
- PUSH_PROMISE from client: GOAWAY PROTOCOL_ERROR

### Stream Concurrency (Section 5.1.2)

- SETTINGS_MAX_CONCURRENT_STREAMS enforced
- Excess streams receive RST_STREAM REFUSED_STREAM
- Active count tracked via readLoop for accurate enforcement

### Flow Control (Section 5.2, 6.9)

- Connection-level and stream-level send/receive windows
- WINDOW_UPDATE with 0 increment on stream 0: GOAWAY PROTOCOL_ERROR
- WINDOW_UPDATE with 0 increment on stream N: RST_STREAM PROTOCOL_ERROR
- Window overflow (>2^31-1): FLOW_CONTROL_ERROR
- SETTINGS_INITIAL_WINDOW_SIZE changes adjust all open stream windows
- Negative send windows tracked; DATA waits for WINDOW_UPDATE to resume

### Frame Validation (Section 6)

- DATA: stream 0 rejected, padding validated
- HEADERS: stream 0 rejected, padding and priority validated
- PRIORITY: stream 0 rejected, 5-byte payload enforced, self-dependency → RST_STREAM
- RST_STREAM: stream 0 rejected, 4-byte payload enforced
- SETTINGS: non-stream-0 rejected, ACK with payload rejected, payload mod 6 enforced
- PUSH_PROMISE: from client → PROTOCOL_ERROR
- PING: non-stream-0 rejected, 8-byte payload enforced
- GOAWAY: non-stream-0 rejected, 8+ byte payload
- WINDOW_UPDATE: 4-byte payload enforced
- CONTINUATION: assembly validated, unexpected/missing → PROTOCOL_ERROR
- Unknown frame types: ignored per Section 4.1

### SETTINGS Validation (Section 6.5)

- ENABLE_PUSH: 0 or 1 only
- INITIAL_WINDOW_SIZE: max 2^31-1
- MAX_FRAME_SIZE: 2^14 to 2^24-1
- Unknown settings IDs: ignored

### HPACK Compliance (RFC 7541)

- Indexed header field: invalid index → COMPRESSION_ERROR
- Literal with invalid name index → COMPRESSION_ERROR
- Dynamic table size update at end of block → COMPRESSION_ERROR
- Dynamic table size update exceeding SETTINGS_HEADER_TABLE_SIZE → COMPRESSION_ERROR
- Huffman decoding validated
- Integer overflow protection

### HTTP Message Validation (Section 8)

- Uppercase header field names → PROTOCOL_ERROR (Section 8.2.1)
- Connection-specific headers (connection, keep-alive, upgrade, proxy-connection, transfer-encoding) → PROTOCOL_ERROR
- TE header with value != "trailers" → PROTOCOL_ERROR (Section 8.2.2)
- Pseudo-header after regular header → PROTOCOL_ERROR
- Duplicate pseudo-headers → PROTOCOL_ERROR
- Unknown pseudo-headers → PROTOCOL_ERROR
- Missing :method → PROTOCOL_ERROR
- Missing :scheme (non-CONNECT) → PROTOCOL_ERROR
- Missing :path (non-CONNECT) → PROTOCOL_ERROR
- Empty :path → PROTOCOL_ERROR
- Content-Length mismatch with DATA payload → PROTOCOL_ERROR

## Security Mitigations

### CVE-2023-44487 (HTTP/2 Rapid Reset Attack)

RST_STREAM frames are counted in a sliding window. If more than 1000 control frames
(PING + SETTINGS + RST_STREAM) arrive within a 10-second window, the server sends
GOAWAY with ENHANCE_YOUR_CALM and closes the connection.

**Test:** `TestRobustness_RapidReset`

### PING Flood Protection

Excessive PING frames trigger GOAWAY ENHANCE_YOUR_CALM.

**Test:** `TestRobustness_PINGFlood`

### SETTINGS Flood Protection

Excessive SETTINGS frames trigger GOAWAY ENHANCE_YOUR_CALM.

**Test:** `TestRobustness_SETTINGSFlood`

### Flow Control Attack Prevention

- Zero-increment WINDOW_UPDATE properly rejected (stream error vs connection error)
- Window overflow detected and rejected with FLOW_CONTROL_ERROR
- Send window blocking with 10-second timeout prevents starvation

## Fuzzing

All parsers fuzz-tested for 20 minutes each (60 minutes total, ~1.36 billion executions):

```
go test -fuzz=FuzzParseRequest ./pkg/header/ -fuzztime=20m   # 308M execs, PASS
go test -fuzz=FuzzHPACKDecode ./pkg/hpack/ -fuzztime=20m     # 539M execs, PASS
go test -fuzz=FuzzReadFrame  ./pkg/frame/ -fuzztime=20m      # 518M execs, PASS
```

### Bugs Found and Fixed

1. **HPACK integer overflow in `decodeString`**: `decodeInteger` returns `uint64`;
   casting a value > `math.MaxInt64` to `int` for slice bounds caused a panic.
   Fixed by comparing `length > uint64(len(data)-n)` before the cast.
   Regression test: `FuzzHPACKDecode/551d461dacc17944`.

## Robustness Test Suite

| Test | Description | Status |
|------|-------------|--------|
| TestRobustness_PINGFlood | 1100 PING frames → GOAWAY ENHANCE_YOUR_CALM | PASS |
| TestRobustness_RapidReset | CVE-2023-44487: rapid open+reset → GOAWAY | PASS |
| TestRobustness_SETTINGSFlood | 1100 SETTINGS frames → GOAWAY ENHANCE_YOUR_CALM | PASS |
| TestRobustness_WindowUpdateZeroStream | 0-increment on stream → RST_STREAM | PASS |
| TestRobustness_WindowUpdateZeroConnection | 0-increment on connection → GOAWAY | PASS |
| TestRobustness_HeadersOnClosedStream | HEADERS on closed stream → GOAWAY STREAM_CLOSED | PASS |
| TestRobustness_EvenStreamID | Even stream ID → GOAWAY PROTOCOL_ERROR | PASS |
| TestRobustness_UppercaseHeaders | Uppercase header name → RST_STREAM PROTOCOL_ERROR | PASS |
