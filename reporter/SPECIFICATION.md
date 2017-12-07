# Reporting specification
This document describes the requirements and models for the reporting
functionality.

## Kind of tests
Goals:
- learn whether enabling TLS 1.3 breaks connections
- learn whether there is a difference with IPv6
- whether a MITM happened that downgraded to lower TLS versions
- if TLS 1.3 is negotiated, whether a MITM happened

Steps that must pass for a test to succeed:
- Client connects to server.
- Handshake
- Client writes request
- Server verifies request, and writes response
- Client verifies response

TODO check compatibility with early data or other TLS 1.3 configurations?

## Workflow
Server receives incoming connection, then responds normally. Optionally it logs
the session if at the start:
 1. Extract (TestID, Number) from SNI. Skip on failure.
 2. Lookup (CreatedAt, IsIPv6, MaxTLSVersion) based on (TestID, Number).
    Skip on failure.
 3. Skip if IsIPv6 does not match the connection.
 4. Check if CreatedAt is older than X minutes. If it is, skip.

At the end condition 4 is also checked, and only if satisfied, the ServerCapture
object is saved.

Client requests test cases and executes them. After a subtest is complete, the
subtest result is sent to the server (only if a connection could be setup).
After completion of the test (all subtests are completed and sent), a comment
form is shown.

## Reporting workflow
Normal users can submit reports only, but privileged users can have
readonly/write access to the results.

Analyst queries:
- How many reports were submitted.
- Summary of reports:
  - Handshake failed
  - Handshake succeeded
    - MITM - lower protocol negotiated
    - Other (OK)

Per-report queries:
- What subtests succeeded/failed?
- pcap for each subtest (client/server view)
- IP/ISP
- Expected TLS version, actual version


## Data model
In the following models, frames is an array of objects (serialized as JSON):
 - Time: time (UTC)
 - IsRead: bool (true if from network, false if written)
 - Data: string (base64-encoded TCP segment bytes)

Primary keys should not be exposed through the API, instead a unique ID (for
example, a UUID) should be used instead (this also applies to foreign keys).
This prevents enumeration.

### Test
A single test run.
- ID: int (primary key)
- TestID: string (externally visible)
- CreatedAt: time
- UpdatedAt: time
- ClientIP: string
- ClientVersion: string (commit of this project)
- FlashVersion: string
- UserAgent: string (navigator.userAgent)
- UserComment: string
- HasFailed: bool (true if any of the captures failed)
- IsMitm: bool (true if any capture suggests that a MITM happened)
- IsPending: bool (true if changes are still accepted)

ClientVersion, FlashVersion, UserAgent exist to detect possible problems with
the test at a later point, allowing bad reports to be discarded.

### Subtest
Records a test configuration and its result.
- ID: int (primary key)
- TestID: foreignKey to Test
- Number: int (unique within a test)
- MaxTLSVersion: uint16
- IsIPv6: bool
- HasFailed: bool
- IsMitm: bool

Note: HasFailed is true if any of the capture results failed.
TODO remove HasFailed here?

A single Test must have a unique (TestID, Number) and should have a unique
(TestID, MaxTLSVersion, IsIPv6).

### ServerCapture
Records the result of a subtest as observed by the server.
- SubtestID: foreignKey to Subtest (internal)
- CreatedAt: time
- BeginTime: time (start of subtest, could be earlier than the first frame)
- EndTime: time (end of subtest, could be later than the last frame)
- ActualTLSVersion: uint16 (negotiated version or 0 on failure)
- Frames
- KeyLog: string
- HasFailed: bool
- ClientIP: string
- ServerIP: string

A single Subtest can have multiple ServerCaptures as weird MITM boxes may exist
that first do a connection to learn about the certificate/capabilities. Not
sure if it is a real problem, but let's be prepared for this possibility.

### ClientCapture
Records the result of a subtest, provided by the client.
- SubtestID: foreignKey to Subtest (internal)
- CreatedAt: time
- BeginTime: time (start of subtest, could be earlier than the first frame)
- EndTime: time (end of subtest, could be later than the last frame)
- ActualTLSVersion: uint16 (negotiated version or 0 on failure)
- Frames
- KeyLog: string
- HasFailed: bool

A Subtest must have a unique ClientCapture.
BeginTime, EndTime, MaxTLSVersion and ActualTLSVersion should match the
information in Frames.

## API
Relevant for determining TLS server to connect to for tests:
- domain: depends on IPv4/IPv6
- hostname (SNI): testid + number + domain. E.g. if TestID is `abcd`, Number is
  `1` and domain is `ipv6.example.com`, use `abcd-1.ipv6.example.com`.

The intention is that the client does not have to care about the exact hostname
contents while the server can parse the hostname and identify the subtest type
(whether it is IPv6 and the maximum TLS version).

Request and response bodies are in JSON unless stated otherwise.
In general PATCH/POST/DELETE requests can fail due to an invalid CSRF token
(403) or ratelimiting.

Captures and comments can no longer be submitted if any of these are true:
- IsPending is false (intended to be changed by the client).
- CreatedAt is older than an hour.
- UpdatedAt is older than 15 minutes.

### POST /tests
Request-Body:
- client\_version: string
- flash\_version: string
- user\_agent: string

Response-Body:
- test\_id: string
- subtests: array of
  - number: string
  - is\_ipv6: bool
  - max\_tls\_version: uint16

### GET /tests
Response-Body:
- result: array of resources `/tests/:testid`.

TODO pagination

### POST /tests/:testid/clientresults
Request-Body:
- begin\_time: time
- end\_time: time
- max\_tls\_version: uint16
- actual\_tls\_version: uint16
- frames: array
- key\_log: string
- has\_failed: bool
- is\_ipv6: bool

Errors:
- 403 - test is readonly, no more changes are allowed.
- 409 - the results for this subtest already exist.

### PATCH /tests/:testid
Request-Body:
- user\_comment: string
- is\_pending: bool (optional, but only `false` is allowed)

Errors:
- 403 - test is readonly, no more changes are allowed.

Note: fields like client\_version are readonly after creation and cannot be
modified. Once `is_pending` is set to `false`, no more captures or patches can
be submitted.

### DELETE /tests/:testid
Removes the results of the given test including its captures.

### GET /tests/:testid
Response-Body:
- test\_id: string
- created\_at: time
- updated\_at: time
- client\_ip: string
- client\_version: string
- flash\_version: string
- user\_agent: string
- user\_comment: string
- has\_failed: bool
- is\_mitm: bool
- is\_pending: bool

TODO hide internal fields like client\_version, flash\_version, user\_agent as
these are probably not relevant for interpreting test results.

### GET /tests/:testid/subtests
Response-Body:
- result: array of resources `/tests/:testid/subtests/:number`.

### GET /tests/:testid/subtests/:number
Response-Body:
- test\_id: string
- numberstring
- max\_tls\_version: uint16
- is\_ipv6: bool
- has\_failed: bool
- is\_mitm: bool

### GET /tests/:testid/client.pcap
Response-Body:
Synthetic libpcap-formatted capture file as seen from the client side containing
the results for all subtests.

The source and destination addresses are looked up from the last server capture
for a given subtest. If no server capture was found for whatever reason, use a
dummy value (like ::1).

### GET /tests/:testid/server.pcap
Response-Body:
Synthetic libpcap-formatted capture file as seen from the server side containing
the results for all subtests.

### GET /tests/:testid/keylog.txt
Response-Body:
Key log file containing all keys used for the client and server captures using
the [NSS Key Log format](https://developer.mozilla.org/NSS_Key_Log_Format).


## Future work
Possible features:
- Detect MITM from frames or HTTP request: user agent mismatch is suspicious.
