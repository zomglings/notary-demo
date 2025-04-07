# TLSNotary Demo

This is a demo of the TLSNotary protocol, which allows for the notarization of TLS sessions.

## Project Structure

- `/common` - Common code shared between the notary and prover
- `/notary` - The notary service that participates in the MPC protocol and provides attestations
- `/prover` - The prover client that requests notarization for TLS sessions

## Components

### Notary

The notary server has two key components:

1. **API Server (port 7151)** - HTTP server that provides:
   - `/api/mpcparams` - Endpoint to discover MPC protocol parameters
   - `/proofs` - List and retrieve notarization proofs
   - `/verifier/verify` - Verify notarization proofs

2. **TLSNotary Server (port 7150)** - MPC protocol server that performs the actual notarization

### Prover

The prover client:

1. Discovers MPC parameters from the notary API
2. Connects to the TLSNotary server to execute the MPC protocol
3. Performs a TLS connection to the target server
4. Notarizes the TLS session
5. Optionally supports selective disclosure of transcript parts

## Running the Demo

### Start the Notary Server

```bash
cargo run --bin notary --release -- --host 127.0.0.1 --port 7150 --api-port 7151
```

### Run the Prover Client

```bash
cargo run --bin prover --release -- \
  --notary-host 127.0.0.1 \
  --notary-port 7150 \
  --notary-api-port 7151 \
  --url https://example.com \
  --method GET
```

You can add selective disclosure with the `--selective-disclosure` option:

```bash
cargo run --bin prover --release -- \
  --notary-host 127.0.0.1 \
  --notary-port 7150 \
  --notary-api-port 7151 \
  --url https://example.com \
  --method GET \
  --selective-disclosure "Authorization:REDACT" \
  --selective-disclosure "token:REDACT"
```

## Implementation

This demo uses the official TLSNotary library with two key components:

1. `notary-server` - Provides the notary service implementation
2. `notary-client` - Client for connecting to the notary service

The implementation follows the attestation example from the TLSNotary repository.

## Architecture

```
+------------+             +------------+            +--------------+
|            |   HTTP API  |            |   HTTPS    |              |
|   Prover   |<----------->|   Notary   |<---------->| Target Site  |
|            |   (7151)    |            |   (443)    |              |
+------------+             +------------+            +--------------+
      ^                          ^
      |                          |
      |      MPC Protocol        |
      |       (7150)             |
      +--------------------------+
```

## Additional Resources

- [Narrative for the demo](./narrative.md)
- [Technical specifications](./spec.md)

## License

MIT