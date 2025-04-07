# TLSNotary Demo Tool (stamp)

A command-line tool for working with TLSNotary servers. This tool simplifies the process of building, configuring, and running TLSNotary servers.

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

Generate ECDSA P-256 key pair for the notary server:

```sh
# Generate ECDSA P-256 keys for the notary server
stamp notary generate-keys --private-key=/path/to/notary.key --public-key=/path/to/notary.pub
```

This command:
- Creates a new ECDSA P-256 key pair
- Saves the private key in PEM format to the specified path
- Saves the public key in PEM format to the specified path

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

