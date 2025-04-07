# TLSNotary Demo

This is a demo of the TLSNotary protocol, which allows for the notarization of TLS sessions.

## Project Structure

- `/common` - Common code shared between the notary and prover
- `/notary` - Our custom API for listing and retrieving notarization proofs
- `/prover` - The prover client that uses the official TLSNotary server

## Components and Architecture

This project uses a hybrid architecture with two servers:

1. **Official notary-server (port 7047)** - Handles the MPC protocol:
   - Provided by the official TLSNotary project
   - Performs the cryptographic notarization process
   - Works with the official NotaryClient library

2. **Our custom API server (port 7048)** - Provides additional features:
   - `/proofs` - List and retrieve notarization proofs
   - `/verifier/verify` - Verify notarization proofs
   - Database storage and management

3. **Prover client** - Connects to the official notary server:
   - Uses the NotaryClient library to communicate with the notary server
   - Performs the TLS connection to the target site
   - Supports selective disclosure of transcript parts

## Setup and Installation

### 1. Install the Official Notary Server

```bash
# Install the official notary-server
cargo install --git https://github.com/tlsnotary/tlsn.git notary-server
```

### 2. Start the Official Notary Server

```bash
# Run on the default port 7047
notary-server --port 7047
```

### 3. Start Our Custom API Server

```bash
# Run our API server on port 7048
cargo run --bin notary -- server -H 127.0.0.1 --api-port 7048 --disable-mpc
```

### 4. Run the Prover Client

```bash
cargo run --bin prover -- -v notarize https://example.com \
  --method GET \
  --notary-host 127.0.0.1 \
  --notary-port 7047
```

You can add selective disclosure with the `--selective-disclosure` option:

```bash
cargo run --bin prover -- -v notarize https://example.com \
  --method GET \
  --notary-host 127.0.0.1 \
  --notary-port 7047 \
  --selective-disclosure "Authorization:REDACT" \
  --selective-disclosure "token:REDACT"
```

## Architecture Diagram

```
                                  +----------------+
                                  |                |
                                  | Target Website |
                                  |                |
                                  +----------------+
                                          ^
                                          |
                                          | HTTPS (443)
                                          |
                                          v
+----------------+        MPC       +-----------------+
|                | <------------->  |                 |
|  Prover Client |      (7047)      | Official Notary |
|                |                  |     Server      |
+----------------+                  +-----------------+
        |
        |                          +-----------------+
        |        REST API          |                 |
        +----------------------->  |   Custom API    |
                 (7048)            |     Server      |
                                   +-----------------+
```

## Additional Resources

- [Narrative for the demo](./narrative.md)
- [Technical specifications](./spec.md)

## License

MIT