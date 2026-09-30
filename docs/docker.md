# OpenSwap Docker

A dockerized version of the **Complete OpenSwap Backend**.

The Docker stack runs up to three containers: `bitcoind`, Tor, and `makerd`. The `makerd` image also holds the `maker-cli` and `taker` apps.

Various subsets of the stack can be used for different application needs and environments.

## Overview

The Docker setup provides a complete environment for running any OpenSwap applications:

- **Single unified Dockerfile** containing all OpenSwap components
- **Alpine Linux 3.20** base image for minimal size
- **Rust 1.90.0** for building the applications
- **Custom Bitcoin Mutinynet image** for Signet testing
- **External Tor image** (`osminogin/tor-simple`)
- **Interactive configuration** with automatic service detection
- **Docker Compose Profiles** for flexible deployment
- **OpenSwap binaries:** `makerd`, `maker-cli`, `taker`

## Architecture

This is an overview for the docker stack with default settings for all nodes:

```mermaid
graph TD
    bitcoind["<b>Bitcoind</b><br/>Bitcoin Node<br/>RPC Port (Default: 38332)<br/>ZMQ Port (Default: 28332)"]
    tor["<b>Tor</b><br/>Tor Proxy<br/>SOCKS Port (Default: 9050)<br/>Control Port (Default: 9051)"]
    makerd["<b>Makerd</b><br/>Network Port (Default: 6102) <br/>RPC Port (Default: 6103)"]
    
    bitcoin_vol["bitcoin-data"]
    tor_vol["tor-data"]
    maker_vol["maker-data"]
    
    makerd <-->|"RPC calls <br> (on bitcoind rpc-port)"| bitcoind
    makerd -->|SOCKS proxy| tor
    makerd -->|Control commands| tor
    
    bitcoind --> bitcoin_vol
    tor --> tor_vol
    makerd --> maker_vol
    
    style bitcoind fill:#f9a825
    style tor fill:#7d4698
    style makerd fill:#3498db
    style bitcoin_vol fill:#ecf0f
    style tor_vol fill:#ecf0f
    style maker_vol fill:#fcf0f
```

All three containers share your host network. Bitcoind RPC and ZMQ and the Tor ports listen only on `127.0.0.1`.

The Docker setup uses:

- `docker/Dockerfile` - Unified image containing `makerd`, `maker-cli`, and `taker`
- `docker/Dockerfile.bitcoin-mutinynet` - Custom Bitcoin Core image for Mutinynet
- `docker-compose.yml` - Single parameterized compose file
- External images: `osminogin/tor-simple` for Tor

## Quick Start

### Using the Setup Script (Recommended)

The `docker-setup` script provides an interactive way to configure and run OpenSwap:

```bash
git clone https://github.com/citadel-foss/openswap.git
cd openswap

# Interactive configuration
./docker-setup configure

# Build the Docker image
./docker-setup build

# (Optional) Build the Bitcoin Mutinynet image if needed
./docker-setup build-bitcoin

# Start the complete stack
./docker-setup start

# Check status
./docker-setup status

# View maker logs with the bundled Tor
./docker-setup logs makerd-internal
# View maker logs with your own Tor
./docker-setup logs makerd
```

### Configuration Options

The setup script will prompt for:

1. **Bitcoin Core Configuration**:
   - Data directory path
   - Network selection (signet or regtest)
   - Use existing Bitcoin Core instance or spawn new one
   - Custom RPC and ZMQ ports

2. **Tor Configuration**:
   - Detect existing Tor instance
   - Use external Tor or spawn containerized version
   - Custom SOCKS and control ports

3. **Service Ports**:
   - Makerd RPC port (default: 6103)

4. **Maker Wallet**:
   - Wallet passphrase. The maker wallet is always encrypted, so makerd needs it on every start.

Configuration is saved to `.docker-config` and reused on subsequent runs. The file holds your RPC password and wallet passphrase, so the script makes it readable only by you.

## Building Docker Images

The build process creates a single image containing all binaries:

```bash
git clone https://github.com/citadel-foss/openswap.git
cd openswap

# Build using the setup script
./docker-setup build

# Build Bitcoin Mutinynet image
./docker-setup build-bitcoin

# Or build manually
docker build -f docker/Dockerfile -t openswap/openswap:latest .
```

### Available Images

- **openswap**: Contains `makerd`, `maker-cli`, and `taker`
- **bitcoin-mutinynet**: Custom Bitcoin Core node for Mutinynet network

## Running Applications

### Makerd (Maker Daemon)

Run the maker daemon with persistent data storage:

```bash
# Using the setup script (recommended)
./docker-setup start

# Or manually, using the Tor and bitcoind on your host
docker run -d \
  --name openswap-makerd \
  --network host \
  -v openswap-maker-data:/home/openswap/.openswap \
  openswap/openswap:latest makerd \
    -r 127.0.0.1:38332 \
    -a user:password \
    -p <wallet-passphrase>
```

The container shares your host network. That way makerd reaches Tor and `bitcoind` on your machine. Makerd always encrypts its wallet. You must set its passphrase with `-p`. Add `-t <tor-password>` if your Tor control port uses a password.

**Ports:**
- `6102`: Maker network port for openswap protocol
- `6103`: Maker RPC port for `maker-cli` commands

### Maker CLI

Control the maker daemon:

```bash
# Using the setup script
./docker-setup maker-cli send-ping
./docker-setup maker-cli get-balances
./docker-setup maker-cli stop

# Or manually, inside the running makerd container
docker exec -it openswap-makerd maker-cli send-ping
docker exec -it openswap-makerd maker-cli get-balances
docker exec -it openswap-makerd maker-cli stop
```

### Taker

Run taker operations:

```bash
# Using the setup script
./docker-setup taker --help

# Or manually
docker run --rm -it \
  -v openswap-taker-data:/home/openswap/.openswap \
  --network host \
  openswap/openswap:latest taker --help
```

## Docker Compose Setup

The setup script uses a standard `docker-compose.yml` with environment variables and profiles. For a complete setup with all services:

```bash
# Start all services (Bitcoin Core, Tor, Makerd)
./docker-setup start

# Note: Running docker compose directly requires setting environment variables.
# It is recommended to use the setup script which handles this for you.

# Check status
./docker-setup status

# View maker logs with the bundled Tor
./docker-setup logs makerd-internal
# View maker logs with your own Tor
./docker-setup logs makerd
```

## Data Persistence

All application data is stored in Docker volumes:

- `bitcoin-data`: Bitcoin blockchain data
- `tor-data`: Tor configuration and data
- `maker-data`: Maker configuration and wallet data

## Troubleshooting

### Check logs

```bash
# using setup script, with the bundled Tor
./docker-setup logs makerd-internal
# using setup script, with your own Tor
./docker-setup logs makerd

# or directly with docker-compose (requires env vars)
docker compose logs -f makerd-internal   # or makerd with your own Tor
```

### Interactive debugging

```bash
# enter container for debugging
./docker-setup shell

# or manually
docker run --rm -it openswap/openswap:latest sh
```
