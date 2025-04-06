# TLSNotary Proof-of-Concept Demo Specification

## Overview

This specification describes the architecture and technical implementation of a web-based demonstration leveraging [TLSNotary](https://github.com/tlsnotary/tlsn) to cryptographically notarize HTTPS responses. The demo includes two Rust backend services (Prover and Notary/Verifier) and elegant HTML/CSS/JS frontends. The goal is to showcase secure selective disclosure and verification of HTTPS response fields.

---

## Architecture

The demo consists of two independent Rust backend servers, each serving their own frontend UI:

### 1. Prover Server (Rust)

**Responsibilities:**

- Provide an interface for users to construct arbitrary HTTPS requests (method, headers, body, URL).
- Perform Multi-Party Computation (MPC) TLS handshakes in collaboration with the Notary server using the [tlsn-prover](https://github.com/tlsnotary/tlsn/tree/main/tlsn-prover) crate.
- Apply selective disclosure to the HTTPS response.
- Submit notarized proofs to the Notary/Verifier server and receive a UUID.

**Frontend (served by Prover server):**

- Minimalist HTML/CSS/JS UI with Matrix-style aesthetics (black background, green monospace font, minimal images).
- User can construct HTTPS requests and specify selective disclosure options.
- Displays UUID returned after proof submission clearly to the user.

---

### 2. Notary/Verifier Server (Rust)

**Responsibilities:**

- Perform cryptographic MPC protocol with Prover using the [tlsn-notary](https://github.com/tlsnotary/tlsn/tree/main/tlsn-notary) crate.
- Receive notarized proofs from the Prover server and assign UUIDs.
- Store notarized proofs in a local SQLite datastore.
- Provide endpoints for retrieval and cryptographic verification of proofs using the [tlsn-verifier](https://github.com/tlsnotary/tlsn/tree/main/tlsn-verifier) crate.

**Frontend (served by Notary/Verifier server):**

- Minimalist HTML/CSS/JS UI with Matrix-style aesthetics (black background, green monospace font, minimal images).
- Provides a list of stored proofs (UUIDs, timestamps, TLS domains).
- Allows users to retrieve and verify proofs using UUIDs.

---

## Technical Stack

### Backend (Rust):

- **TLSNotary Crates** ([GitHub](https://github.com/tlsnotary/tlsn), [Docs](https://docs.tlsnotary.org)):
  - Prover functionality: [`tlsn-prover`](https://github.com/tlsnotary/tlsn/tree/main/tlsn-prover)
  - Notary functionality: [`tlsn-notary`](https://github.com/tlsnotary/tlsn/tree/main/tlsn-notary)
  - Verifier functionality: [`tlsn-verifier`](https://github.com/tlsnotary/tlsn/tree/main/tlsn-verifier)

- **HTTP Server Framework:**
  - [Actix-web](https://github.com/actix/actix-web) or [Rocket](https://github.com/SergioBenitez/Rocket)

- **UUID Generation:**
  - [`uuid`](https://github.com/uuid-rs/uuid)

- **JSON Serialization/Deserialization:**
  - [`serde`](https://github.com/serde-rs/serde)
  - [`serde_json`](https://github.com/serde-rs/json)

- **SQLite Datastore:**
  - [`rusqlite`](https://github.com/rusqlite/rusqlite)

---

### Frontend (HTML/CSS/JS):

- Served directly from Rust backends as static files.
- No JavaScript frameworks (no React, Next.js, etc.).
- Styled using pure CSS.  
- Matrix-inspired aesthetics:
  - Black background (`#000`).
  - Green monospace text (`#00FF00`), recommended font: [Fira Code](https://github.com/tonsky/FiraCode) (or fallback to system monospace fonts).
  - Minimal images/graphics; focus on functional elegance.

---

## Data Flow and Workflow

### Prover Side (Doctor Perspective)

**Frontend UI** (`Prover Server`):

1. Doctor constructs HTTPS request specifying:
   - HTTP method
   - URL
   - Headers
   - Optional request body

2. Doctor specifies response fields to disclose or redact.

3. Doctor clicks **"Generate & Submit Proof"** button.

**Backend Logic** (`Prover Server`):

1. Performs MPC handshake using [`tlsn-prover`](https://github.com/tlsnotary/tlsn/tree/main/tlsn-prover) with Notary server.
2. Makes HTTPS request securely via TLSNotary MPC.
3. Receives HTTPS response and applies selective disclosure.
4. Submits notarized proof to Notary/Verifier server (`POST /proofs`).
5. Receives generated UUID from Notary/Verifier server.
6. Returns UUID to frontend UI for the Doctor to copy and share.

---

### Notary/Verifier Side (Dave's Perspective)

**Proof Storage** (`Notary/Verifier Server`):

- Receives proofs at endpoint (`POST /proofs`).
- Generates UUID using [`uuid`](https://github.com/uuid-rs/uuid) crate.
- Stores proof JSON, UUID, TLS domain, and timestamp into SQLite database.

**Frontend UI** (`Notary/Verifier Server`):

1. Lists all stored proofs with UUID, domain, and creation timestamps.

2. Allows Dave to input a UUID directly to retrieve a specific proof.

3. Dave clicks **"Verify Proof"**.

**Backend Logic** (`Notary/Verifier Server`):

- Retrieves proof from SQLite.
- Verifies cryptographic validity (signature, domain, selective disclosure) using [`tlsn-verifier`](https://github.com/tlsnotary/tlsn/tree/main/tlsn-verifier).
- Returns verification status and disclosed fields to frontend.

---

## Database Schema (SQLite)

```sql
CREATE TABLE notarized_proofs (
  id TEXT PRIMARY KEY,           -- UUID
  tls_domain TEXT NOT NULL,      -- TLS certificate domain (e.g., api.acme.com)
  proof_json TEXT NOT NULL,      -- Serialized notarized proof
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
````

## REST API Endpoints

### Prover Server

| Method | Endpoint          | Purpose                                                             |
|--------|-------------------|---------------------------------------------------------------------|
| `POST` | `/generate_proof` | Performs TLSNotary MPC handshake and selective disclosure; returns notarized proof |

### Notary/Verifier Server

| Method | Endpoint             | Purpose                                    |
|--------|----------------------|--------------------------------------------|
| `POST` | `/proofs`            | Receives notarized proofs; returns UUID    |
| `GET`  | `/proofs`            | Retrieves a list of all stored proofs      |
| `GET`  | `/proofs/{uuid}`     | Retrieves a specific proof by UUID         |
| `POST` | `/verifier/verify`   | Cryptographically verifies the given proof |

---

## UI Design Guidelines (Both Frontends)

- **Aesthetics**: Black background (`#000`), green monospace font (`#00FF00`).
- **Font**: [Fira Code](https://github.com/tonsky/FiraCode) or fallback monospace.
- Minimal graphical elements; emphasize clean, text-based presentation.
- Matrix-inspired, hacker aesthetic.

---

## External References and Documentation

- [TLSNotary GitHub Repository](https://github.com/tlsnotary/tlsn)
- [TLSNotary Official Documentation](https://docs.tlsnotary.org/)
- [Actix-web Framework](https://github.com/actix/actix-web)
- [Rocket Web Framework](https://github.com/SergioBenitez/Rocket)
- [`serde` Serialization](https://github.com/serde-rs/serde)
- [`serde_json` JSON handling](https://github.com/serde-rs/json)
- [`rusqlite` SQLite Interface](https://github.com/rusqlite/rusqlite)
- [`uuid` Crate](https://github.com/uuid-rs/uuid)
- [Fira Code Font](https://github.com/tonsky/FiraCode)

---

## Implementation Notes

- **Authentication**: No authentication required for this demo.
- **Deployment**: Servers should run locally or on a simple host for easy testing and minimal latency.
- **Security**: For production use, consider implementing proper authentication, encrypted storage, robust error handling, and secure channels.

---
