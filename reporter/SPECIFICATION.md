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
 1. Split SNI into (TestID, IPv6, MaxTLSVersion). Skip on failure.
 2. Check if Test model (based on TestID) is known. If not, skip.
 4. Check if CreateTime is older than X minutes. If it is, skip.

At the end these conditions are also checked, and only if satisfied, the
ServerCapture model is saved.

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


## DATA MODEL
Test
- TestID: string
- CreateTime: time
- UpdateTime: time
- ClientIP: string
- ClientVersion: string (commit of this project)
- FlashVersion: string
- UserAgent: string (navigator.userAgent)
- UserComment: string

ClientVersion, FlashVersion, UserAgent exist to detect possible problems with
the test at a later point, allowing bad reports to be discarded.


ServerCapture
- TestID: foreignKey to Test.TestID
- BeginTime: time
- EndTime: time
- MaxTLSVersion: uint16
- Frames
- KeyLog: string
- Result: bool
- ClientIP: string
- ServerIP: string

A single Test can have multiple ServerCaptures as weird MITM boxes may exist
that first do a connection to learn about the certificate/capabilities. Not
sure if it is a real problem, but let's be prepared for this possibility.


ClientCapture:
- TestID: foreignKey to Test.TestID
- BeginTime: time
- EndTime: time
- MaxTLSVersion: uint16
- Frames
- KeyLog: string
- Result: bool

A single Test must have a unique (TestID, MaxTLSVersion).


Frames is an array of objects (serialized as JSON):
 - Time: time (UTC)
 - IsRead: bool (true if from network, false if written)
 - Data: string (base64-encoded TCP segment bytes)


## API
TODO reporting functionality needs more consideration

Relevant for determining TLS server to connect to for tests:
- domain: depends on IPv4/IPv6
- SNI: subtestid + domain

### POST /tests/new
Request-Body:
- clientversion: string
- flashversion: string
- useragent: string

Response-Body:
- testid: string
- tests: array
  - subtestid: string
  - ipv6: bool
  - version: uint16

### PUT /tests/:testid/results/:subtestid:
Request-Body:
- frames: array
- keylog: string
- result: bool

### PUT /tests/:testid/comment
Request-Body:
- comment: string

### GET /tests/:testid
Response-Body:
(model contents)

### GET /tests/:testid/results
Response-Body:
(array of model contents)
