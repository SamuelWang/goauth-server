#!/bin/bash
# Script to generate ES256 (ECDSA P-256) keys for JWT signing

set -e

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
CERT_DIR="$REPO_ROOT/.cert"

mkdir -p "$CERT_DIR"

PRIVATE_KEY_FILE=".cert/jwt-private.pem"
PUBLIC_KEY_FILE=".cert/jwt-public.pem"

echo "Generating ES256 (ECDSA P-256) key pair for JWT..."

# Generate private key
openssl ecparam -name prime256v1 -genkey -noout -out "$PRIVATE_KEY_FILE"
echo "✓ Private key generated: $PRIVATE_KEY_FILE"

# Generate public key from private key
openssl ec -in "$PRIVATE_KEY_FILE" -pubout -out "$PUBLIC_KEY_FILE"
echo "✓ Public key generated: $PUBLIC_KEY_FILE"

echo ""
echo "Keys generated successfully!"
echo ""
echo "Next steps:"
echo "1. Copy the contents of $PRIVATE_KEY_FILE (including BEGIN/END markers) to ACCESS_TOKEN_PRIVATE_KEY in your .env file"
echo "2. Copy the contents of $PUBLIC_KEY_FILE (including BEGIN/END markers) to ACCESS_TOKEN_PUBLIC_KEY in your .env file"
echo ""
echo "For multi-line values in .env, use:"
echo 'ACCESS_TOKEN_PRIVATE_KEY="-----BEGIN EC PRIVATE KEY-----'
echo 'Your private key here'
echo '-----END EC PRIVATE KEY-----"'
echo ""
echo "IMPORTANT: Keep these files secure and never commit them to version control!"
