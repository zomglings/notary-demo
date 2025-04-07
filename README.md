# TLSNotary Demo Tool (stamp)

A command-line tool for working with TLSNotary servers. This tool simplifies the process of building, configuring, running TLSNotary servers, and proving arbitrary API calls.

## Documentation

- [Narrative for the demo](./narrative.md)
- [Technical specifications](./spec.md)

## Quickstart

### Installing

Clone this repository and build using Cargo:

```sh
git clone https://github.com/yourusername/notary-demo.git
cd notary-demo
cargo build --release
```

The binary will be available at `target/release/stamp`.

### Working with the TLSNotary Server

The `stamp` tool provides several commands for working with TLSNotary servers. Here's how to use them:

## TLSNotary Server Setup Guide

### Step 1: Build the TLSNotary Server

First, build the TLSNotary server from source:

```sh
# Build the TLSNotary server and save it to the specified output file
stamp notary build --outfile=/path/to/notary-server
```

This command:
- Initializes the git submodule containing the TLSNotary source code (if needed)
- Builds the notary server in release mode
- Copies the binary to the specified output file

### Step 2: Generate Signing Keys

Generate ECDSA key pair for the notary server:

```sh
# Generate ECDSA P-256 keys (default)
stamp notary keygen --private-key=/path/to/notary.key --public-key=/path/to/notary.pub

# Generate ECDSA P-256 keys explicitly
stamp notary keygen --private-key=/path/to/notary.key --public-key=/path/to/notary.pub --curve p256

# Generate ECDSA secp256k1 keys
stamp notary keygen --private-key=/path/to/notary.key --public-key=/path/to/notary.pub --curve secp256k1
```

This command:
- Creates a new ECDSA key pair using the specified elliptic curve (P-256 by default or secp256k1)
- Saves the private key in PEM format to the specified path
- Saves the public key in PEM format to the specified path

Note: Use secp256k1 curve if you need compatibility with certain TLSNotary prover clients.

### Step 3: Create a Configuration File

Create a configuration file for the TLSNotary server:

```sh
# Create a basic configuration file
stamp notary configure --outfile=/path/to/config.yaml

# Create a configuration with custom host and port
stamp notary configure --outfile=/path/to/config.yaml --host=127.0.0.1 --port=8443

# Create a configuration with TLS enabled
stamp notary configure --outfile=/path/to/config.yaml --tls-enabled=true \
  --tls-certificate=/path/to/cert.pem --tls-private-key=/path/to/key.pem

# Use custom notary signing keys
stamp notary configure --outfile=/path/to/config.yaml \
  --notary-private-key=/path/to/notary.key --notary-public-key=/path/to/notary.pub
```

Configuration options:
- `--outfile`: Path to the output configuration file (required)
- `--host`: Host address to bind the server to (default: 0.0.0.0)
- `--port`: Port to run the server on (default: 7047)
- `--tls-enabled`: Whether to enable TLS for the server (default: false)
- `--tls-certificate`: Path to the TLS certificate file
- `--tls-private-key`: Path to the TLS private key file
- `--notary-private-key`: Path to the notary private key file
- `--notary-public-key`: Path to the notary public key file

### Step 4: Run the TLSNotary Server

Start the TLSNotary server using the generated configuration:

```sh
# Run the notary server with a configuration file
stamp notary serve --notary-bin=/path/to/notary-server --config=/path/to/config.yaml
```

Server options:
- `--notary-bin`: Path to the notary server binary (required)
- `--config`: Path to the configuration file
- `--certs-dir`: Path to the certificates directory (optional, for information only)

## Certificate Management

The tool also provides commands for generating self-signed certificates:

```sh
# Generate self-signed certificates for a domain
stamp certs --domain example.com --outdir /path/to/certs

# Generate certificates with multiple domain names (SAN)
stamp certs --domain example.com --aliases www.example.com,api.example.com --outdir /path/to/certs
```

Certificate options:
- `--domain`: Domain name for the certificate (required)
- `--aliases`: Additional domain aliases (Subject Alternative Names)
- `--outdir`: Output directory for the certificates (required)
- `--prefix`: Prefix for certificate filenames

## Making HTTP Requests

The `stamp request` command allows you to make arbitrary HTTP requests with custom methods, headers, and body content. This is useful for testing APIs and debugging.

```sh
# Make a simple GET request
stamp request https://example.com

# Make a request with custom headers and method
stamp request https://api.example.com \
  --method POST \
  --header "Content-Type:application/json" \
  --body '{"key": "value"}'
  
# Save the response to a file
stamp request https://example.com --outfile response.txt

# Connect to the TLSNotary server fixture using HTTP/0.9
stamp request http://127.0.0.1:4000 \
  --header "Host:tlsnotary.org" \
  --header "X-Use-HTTP09:true"
```

Options:
- `--method`: HTTP method (GET, POST, PUT, DELETE, etc.)
- `--header`: HTTP headers in format "key:value" (can be specified multiple times)
- `--body`: Request body content
- `--outfile`: File to save the response to (instead of printing to console)

### HTTP/0.9 Support

For testing with the TLSNotary server fixture, use the special header `X-Use-HTTP09:true` to enable HTTP/0.9 mode, which uses a direct TCP connection with simple HTTP protocol formatting. This is particularly useful for the TLSNotary server fixture, which uses HTTP/0.9.

```sh
# Testing the TLSNotary server fixture (running on port 4000)
cargo run -- request http://127.0.0.1:4000 \
  --header "Host:tlsnotary.org" \
  --header "X-Use-HTTP09:true"

# With POST method and JSON body
cargo run -- request http://127.0.0.1:4000 \
  --header "Host:tlsnotary.org" \
  --header "X-Use-HTTP09:true" \
  --method POST \
  --body '{"test":"data"}'
```

**Note about the Server Fixture**: The TLSNotary server fixture is a minimal test server designed specifically for testing the TLSNotary protocol. It responds with a simple " 2" message regardless of the endpoint, method, or headers used. This is expected behavior as the fixture focuses on providing a consistent, simple response for testing TLS notarization rather than serving real content.

## Proving API Calls with TLSNotary

The `stamp` tool allows you to notarize arbitrary HTTPS API calls, create verifiable presentations with selective disclosure, and verify these presentations. This enables you to prove that an API returned specific data without revealing your credentials or other sensitive information.

### Step 1: Notarize an API Call

Make an HTTPS request and notarize it:

```sh
# Make a basic GET request
stamp prover notarize https://api.example.com/endpoint

# Make a request with custom method and headers
stamp prover notarize https://api.example.com/endpoint \
  --method POST \
  --header "Content-Type:application/json" \
  --header "Authorization:Bearer your_token" \
  --body '{"query": "example"}' \
  --outfile my-notarization

# Specify a custom notary server
stamp prover notarize https://api.example.com/endpoint \
  --notary-host 127.0.0.1 \
  --notary-port 7047
```

This command:
- Connects to the notary server (default: 127.0.0.1:7047)
- Makes the HTTPS request to the specified URL
- Creates an attestation of the TLS session
- Saves the attestation and secrets to files (default: `notarization.attestation.bin` and `notarization.secrets.bin`)

### Step 2: Create a Verifiable Presentation

Create a presentation that selectively reveals parts of the notarized session:

```sh
# Create a basic presentation
stamp prover present \
  --attestation my-notarization.attestation.bin \
  --secrets my-notarization.secrets.bin \
  --outfile my-presentation.bin

# Redact sensitive headers
stamp prover present \
  --attestation my-notarization.attestation.bin \
  --secrets my-notarization.secrets.bin \
  --redact-request-header "Authorization" \
  --redact-request-header "Cookie" \
  --outfile my-presentation.bin

# Redact request body (e.g., credentials) but show response
stamp prover present \
  --attestation my-notarization.attestation.bin \
  --secrets my-notarization.secrets.bin \
  --redact-request-body \
  --outfile my-presentation.bin
```

This command:
- Loads the attestation and secrets from the specified files
- Creates a presentation with selective disclosure based on the specified redactions
- Saves the presentation to the specified output file

### Step 3: Verify a Presentation

Verify and display the contents of a presentation:

```sh
# Verify a presentation
stamp prover verify my-presentation.bin
```

This command:
- Loads and cryptographically verifies the presentation
- Displays information about the verified session:
  - Server name
  - Connection time
  - Request and response data with redacted (undisclosed) parts marked with 'X'

### Example Use Cases

1. **Proving API responses**: Prove that an API returned specific data at a certain time
2. **Selective disclosure**: Reveal specific parts of an API response while hiding your credentials
3. **Verifiable quotes**: Notarize price quotes from an API without revealing your identity
4. **Data integrity**: Prove that data came from a specific API without modification

