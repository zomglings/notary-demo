# TLSNotary Demo - Current Implementation Context

## Components Implemented

### 1. Notary Server
- TCP listener on port 7150 for TLSNotary MPC protocol
- Handles connections from provers
- Performs cryptographic notarization using tlsn-verifier
- Stores proofs in SQLite database
- Protocol implementation with proper limits and timeouts

### 2. Prover Client
- Command-line interface for making notarized HTTPS requests
- Connects to notary server for MPC-TLS handshake
- Makes HTTPS requests through TLSNotary protocol
- Implements selective disclosure of content
- Outputs cryptographic proofs as JSON

### 3. Database and Storage
- SQLite database for storing notarized proofs
- Schema with UUID, domain, proof JSON, and timestamp
- Access methods for retrieving and verifying proofs

## Narrative Context
- Demo showcases secure selective disclosure of credential information
- Dr. Pierce (Prover) - Medical professional who wants to prove credentials while preserving privacy
- Dave (Verifier) - Patient who needs to verify doctor's credentials
- ACME - External credentialing service providing official credential data via HTTPS API

## Implementation Details

### Notary Service (tlsn_service.rs)
- TcpListener on host:port (default 127.0.0.1:7150)
- Accepts connections from provers
- Performs MPC protocol for TLS notarization
- Stores resulting proofs in database with UUID

### Prover Client (prover/*.rs)
- CLI interface with options for URL, method, headers, body
- Selective disclosure options for controlling what's revealed
- Connects to notary via TCP for MPC protocol
- Connects to target HTTPS server for secure data access
- Generates proofs with cryptographic guarantees

## Configuration Settings
- MAX_SENT_DATA: 64KB (request size limit)
- MAX_RECV_DATA: 1MB (response size limit)
- MPC_TIMEOUT_SECS: 60 seconds (protocol timeout)

## Current State
Both the notary server and prover client have been implemented with their core functionality. The system allows for:
1. Running a notary server that accepts TCP connections on port 7150
2. Using the prover CLI to connect to websites and generate notarized proofs
3. Applying selective disclosure to control what information is revealed
4. Storing and retrieving proofs via UUID

The implementation follows the TLSNotary protocol for secure, non-interactive proofs of TLS sessions with selective disclosure capabilities.