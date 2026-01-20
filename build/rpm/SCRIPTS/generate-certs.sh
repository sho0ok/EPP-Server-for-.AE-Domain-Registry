#!/bin/bash
#
# EPP Server Certificate Generator
#

CERT_DIR="/etc/epp-server/tls"

echo "Generating EPP Server TLS certificates..."
echo ""

# Create directory if not exists
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Generate CA
echo "[1/5] Generating CA private key..."
openssl genrsa -out ca.key 2048 2>/dev/null

echo "[2/5] Generating CA certificate..."
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/C=AE/O=AE Registry/CN=EPP CA" 2>/dev/null

# Generate Server certificate
echo "[3/5] Generating server private key..."
openssl genrsa -out server.key 2048 2>/dev/null

echo "[4/5] Generating server certificate request..."
openssl req -new -key server.key -out server.csr \
    -subj "/C=AE/O=AE Registry/CN=epp.aeda.ae" 2>/dev/null

echo "[5/5] Signing server certificate..."
openssl x509 -req -days 3650 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt 2>/dev/null

# Generate sample client certificate (for testing)
echo ""
echo "Generating sample client certificate for testing..."
openssl genrsa -out client.key 2048 2>/dev/null
openssl req -new -key client.key -out client.csr \
    -subj "/C=AE/O=Test Registrar/CN=test-registrar" 2>/dev/null
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt 2>/dev/null

# Set permissions
chown epp:epp "$CERT_DIR"/*
chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

# Clean up CSR files
rm -f "$CERT_DIR"/*.csr

echo ""
echo "=========================================="
echo "Certificates generated successfully!"
echo "=========================================="
echo ""
echo "Files created in $CERT_DIR:"
echo "  ca.crt       - CA certificate"
echo "  ca.key       - CA private key"
echo "  server.crt   - Server certificate"
echo "  server.key   - Server private key"
echo "  client.crt   - Test client certificate"
echo "  client.key   - Test client private key"
echo ""
echo "For production, replace with your own certificates."
echo ""
