#!/bin/bash
#
# EPP Server TLS Certificate Generator
#
# Generates:
# 1. CA certificate and key (for signing client certs)
# 2. Server certificate and key (for EPP server)
# 3. Sample client certificate (for testing)
#
# For production, use certificates from your organization's CA
#

set -e

# Configuration
CERT_DIR="${1:-/opt/epp-server/config/tls}"
DAYS_VALID="${2:-3650}"  # 10 years default
KEY_SIZE=4096
SERVER_CN="${3:-epp.aeda.ae}"
CA_CN="AEDA EPP Certificate Authority"
CLIENT_CN="${4:-test-registrar}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}EPP Server Certificate Generator${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Certificate directory: ${CERT_DIR}"
echo "Validity period: ${DAYS_VALID} days"
echo "Server CN: ${SERVER_CN}"
echo ""

# Create directory
mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

# Check if certificates already exist
if [ -f "ca.crt" ] || [ -f "server.crt" ]; then
    echo -e "${YELLOW}WARNING: Certificates already exist in ${CERT_DIR}${NC}"
    read -p "Overwrite? (y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "Aborted."
        exit 0
    fi
fi

echo ""
echo -e "${GREEN}[1/4] Generating CA certificate...${NC}"

# Generate CA private key
openssl genrsa -out ca.key ${KEY_SIZE}
chmod 600 ca.key

# Generate CA certificate
openssl req -new -x509 -days ${DAYS_VALID} -key ca.key -out ca.crt \
    -subj "/CN=${CA_CN}/O=AEDA/C=AE"

echo "  Created: ca.key, ca.crt"

echo ""
echo -e "${GREEN}[2/4] Generating server certificate...${NC}"

# Generate server private key
openssl genrsa -out server.key ${KEY_SIZE}
chmod 600 server.key

# Create server certificate config
cat > server.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${SERVER_CN}
O = AEDA
C = AE

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SERVER_CN}
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

# Generate server CSR
openssl req -new -key server.key -out server.csr -config server.cnf

# Sign server certificate with CA
openssl x509 -req -days ${DAYS_VALID} -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -extensions v3_req -extfile server.cnf

echo "  Created: server.key, server.crt"

echo ""
echo -e "${GREEN}[3/4] Generating sample client certificate...${NC}"

# Generate client private key
openssl genrsa -out client.key ${KEY_SIZE}
chmod 600 client.key

# Create client certificate config
cat > client.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${CLIENT_CN}
O = Test Registrar
C = AE

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# Generate client CSR
openssl req -new -key client.key -out client.csr -config client.cnf

# Sign client certificate with CA
openssl x509 -req -days ${DAYS_VALID} -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -extensions v3_req -extfile client.cnf

echo "  Created: client.key, client.crt"

echo ""
echo -e "${GREEN}[4/4] Creating CA bundle and cleaning up...${NC}"

# Create CA bundle (for client verification)
cp ca.crt ca-bundle.crt

# Clean up temporary files
rm -f server.csr server.cnf client.csr client.cnf ca.srl

# Set permissions
chmod 644 ca.crt ca-bundle.crt server.crt client.crt
chmod 600 ca.key server.key client.key

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Certificate generation complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Files created in ${CERT_DIR}:"
echo ""
echo "  CA Certificate:"
echo "    ca.crt          - CA certificate (distribute to clients)"
echo "    ca.key          - CA private key (keep secure!)"
echo "    ca-bundle.crt   - CA bundle for client verification"
echo ""
echo "  Server Certificate:"
echo "    server.crt      - Server certificate"
echo "    server.key      - Server private key"
echo ""
echo "  Sample Client Certificate:"
echo "    client.crt      - Client certificate (CN=${CLIENT_CN})"
echo "    client.key      - Client private key"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "  1. Keep ca.key and server.key secure (chmod 600)"
echo "  2. Distribute ca.crt to registrars for verification"
echo "  3. For production, use certificates from your organization's CA"
echo "  4. The client CN (${CLIENT_CN}) is used as the registrar ID"
echo ""
echo "Configuration for /opt/epp-server/config/epp.yaml:"
echo ""
echo "  tls:"
echo "    cert_file: ${CERT_DIR}/server.crt"
echo "    key_file: ${CERT_DIR}/server.key"
echo "    ca_file: ${CERT_DIR}/ca-bundle.crt"
echo ""
