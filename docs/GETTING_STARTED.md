# Getting Started

This guide explains how to fork, setup, and run the EPP Server and Client toolkit.

## Fork & Clone

### 1. Fork the Repository

1. Go to https://github.com/sho0ok/EPP-Server-for-.AE-Domain-Registry
2. Click the **"Fork"** button (top right corner)
3. This creates a copy under your GitHub account

### 2. Clone to Your Computer

```bash
git clone https://github.com/YOUR-USERNAME/EPP-Server-for-.AE-Domain-Registry.git
cd EPP-Server-for-.AE-Domain-Registry
```

---

## EPP Server Setup

### 1. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Database

```bash
# Copy example config
cp .env.example .env

# Edit with your database credentials
nano .env
```

Example `.env` file:
```
DB_HOST=your-oracle-host.example.com
DB_PORT=1521
DB_SERVICE=EPPDB
DB_USER=epp_user
DB_PASSWORD=your_secure_password

EPP_HOST=0.0.0.0
EPP_PORT=700
LOG_LEVEL=INFO
```

### 4. Setup Certificates

```bash
mkdir -p certs
cd certs

# Generate CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/C=AE/ST=Abu Dhabi/O=Your Registry/CN=EPP CA"

# Generate server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/C=AE/ST=Abu Dhabi/O=Your Registry/CN=epp.yourdomain.ae"
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt

cd ..
```

### 5. Run the Server

```bash
python3 -m src.main
```

---

## EPP Client Setup

### 1. Navigate to Client Directory

```bash
cd client
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows
```

### 3. Install the Client

```bash
pip install -e .
```

### 4. Generate Client Certificate

```bash
mkdir -p ~/epp-certs
cd ~/epp-certs

# Generate client key and CSR
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
    -subj "/C=AE/ST=Dubai/O=Your Company/CN=your-registrar-id"

# Get this CSR signed by the registry CA
# They will return client.crt and ca.crt
```

### 5. Configure CLI

Create `~/.epp/config.yaml`:

```yaml
profiles:
  default:
    server:
      host: epp.registry.ae
      port: 700
      timeout: 30
    credentials:
      client_id: your-registrar-id
    certs:
      cert_file: ~/epp-certs/client.crt
      key_file: ~/epp-certs/client.key
      ca_file: ~/epp-certs/ca.crt
```

### 6. Test Connection

```bash
export EPP_PASSWORD='your-password'
epp hello
```

---

## Quick Test with Mock Server

For testing without a real server:

### 1. Generate Test Certificates

```bash
mkdir -p ~/test-certs
cd ~/test-certs

# CA
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/CN=Test CA"

# Server
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt

# Client
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=testclient"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt
```

### 2. Update Mock Server Certificate Path

Edit `client/tests/mock_server.py` line 21:
```python
CERT_DIR = Path(os.path.expanduser("~/test-certs"))
```

### 3. Start Mock Server

```bash
cd client
python3 tests/mock_server.py &
```

### 4. Test Commands

```bash
epp --host localhost --port 7700 \
    --cert ~/test-certs/client.crt \
    --key ~/test-certs/client.key \
    --ca ~/test-certs/ca.crt \
    -u testregistrar -P testpass \
    domain check example.ae
```

---

## Project Structure

```
EPP-Server-for-.AE-Domain-Registry/
├── src/                    # EPP Server source code
│   ├── core/               # Core server components
│   ├── commands/           # EPP command handlers
│   ├── database/           # Database models & repositories
│   └── utils/              # Utilities
├── client/                 # EPP Client toolkit
│   ├── src/
│   │   ├── epp_client/     # Python client library
│   │   └── epp_cli/        # Command-line interface
│   ├── tests/              # Tests & mock server
│   └── examples/           # Usage examples
├── config/                 # Configuration files
└── docs/                   # Documentation
```

---

## Next Steps

- Read `client/TESTING_GUIDE.md` for detailed command examples
- Check `client/examples/` for Python API usage
- See `client/README.md` for full client documentation

---

## Need Help?

- Open an issue on GitHub
- Check existing issues for solutions
