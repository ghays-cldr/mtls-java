#!/bin/bash

# Script to create a Java keystore with a certificate
# This creates keystores using CA-signed certificates (localhost+2.pem)
# Usage: ./create-keystore.sh [-client|-server]

# Function to display usage
usage() {
    echo "Usage: $0 [-all|-client|-server] [-single-use]"
    echo "  -all        Create both client.jks and server.jks keystores plus truststore.jks (default)"
    echo "  -client     Create client.jks keystore with client certificate only"
    echo "  -server     Create server.jks keystore with server certificate only"
    echo "  -single-use Set serverAuth EKU in client certificate for single-use scenarios"
    exit 1
}

# Parse command line arguments
KEYSTORE_TYPE="all"
SINGLE_USE=false

while [ $# -gt 0 ]; do
    case "$1" in
        -all)
            KEYSTORE_TYPE="all"
            ;;
        -client)
            KEYSTORE_TYPE="client"
            ;;
        -server)
            KEYSTORE_TYPE="server"
            ;;
        -single-use)
            SINGLE_USE=true
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Error: Unknown argument '$1'"
            usage
            ;;
    esac
    shift
done

# Configuration based on keystore type
KEYSTORE_PASSWORD="changeit"
VALIDITY_DAYS=365
KEY_SIZE=2048

# CA certificate and key files
CA_CERT="./ca-cert.pem"
CA_KEY="./ca-key.pem"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to create a keystore for a specific type (client or server)
create_keystore() {
    local TYPE=$1
    local KEYSTORE_NAME="${TYPE}.jks"
    local KEY_ALIAS="$TYPE"
    
    echo -e "${GREEN}Creating Java keystore: ${KEYSTORE_NAME} (${TYPE})${NC}"
    echo "=============================================="
    
    # Create proper subject name for the certificate
    if [ "$TYPE" = "server" ]; then
        CERT_SUBJECT="/CN=localhost/OU=Development/O=MyOrg/L=City/ST=State/C=US"
    else
        CERT_SUBJECT="/CN=client/OU=Development/O=MyOrg/L=City/ST=State/C=US"
    fi

    # Remove existing keystore if it exists
    if [ -f "$KEYSTORE_NAME" ]; then
        echo -e "${YELLOW}Warning: $KEYSTORE_NAME already exists. Removing it...${NC}"
        rm "$KEYSTORE_NAME"
    fi

    # Remove temporary files if they exist
    rm -f temp_${TYPE}_cert.pem temp_${TYPE}_key.pem temp_${TYPE}.p12 temp_${TYPE}_req.pem

    # Generate a certificate signed by the CA
    echo -e "${GREEN}Generating ${TYPE} certificate signed by CA...${NC}"

    # Create a certificate request (disable Git Bash path conversion)
    MSYS_NO_PATHCONV=1 openssl req -new -newkey rsa:${KEY_SIZE} -nodes \
        -keyout temp_${TYPE}_key.pem \
        -out temp_${TYPE}_req.pem \
        -subj "$CERT_SUBJECT"

    # Check if CSR was created successfully
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to create certificate signing request for ${TYPE}${NC}"
        rm -f temp_${TYPE}_key.pem temp_${TYPE}_req.pem
        return 1
    fi

    # Sign the certificate with the CA
    if [ "$TYPE" = "server" ]; then
        # Create extensions file for server certificate
        cat > temp_server_ext.cnf << EOF
[v3_req]
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF
        
        openssl x509 -req -in temp_${TYPE}_req.pem \
            -CA "$CA_CERT" -CAkey "$CA_KEY" \
            -CAcreateserial -out temp_${TYPE}_cert.pem \
            -days "$VALIDITY_DAYS" \
            -extensions v3_req -extfile temp_server_ext.cnf
        
        # Check if certificate was signed successfully
        if [ $? -ne 0 ]; then
            echo -e "${RED}Error: Failed to sign server certificate${NC}"
            rm -f temp_server_ext.cnf temp_${TYPE}_key.pem temp_${TYPE}_req.pem temp_${TYPE}_cert.pem
            return 1
        fi
        
        rm -f temp_server_ext.cnf
    else
        # Create extensions file for client certificate
        if [ "$SINGLE_USE" = true ]; then
            # Single-use client certificate with serverAuth EKU
            cat > temp_client_ext.cnf << EOF
[v3_req]
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = client
EOF
            echo -e "${YELLOW}Creating single-use client certificate with serverAuth EKU...${NC}"
        else
            # Standard client certificate with clientAuth EKU
            cat > temp_client_ext.cnf << EOF
[v3_req]
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = client
EOF
        fi
        
        openssl x509 -req -in temp_${TYPE}_req.pem \
            -CA "$CA_CERT" -CAkey "$CA_KEY" \
            -CAcreateserial -out temp_${TYPE}_cert.pem \
            -days "$VALIDITY_DAYS" \
            -extensions v3_req -extfile temp_client_ext.cnf
        
        # Check if certificate was signed successfully
        if [ $? -ne 0 ]; then
            echo -e "${RED}Error: Failed to sign client certificate${NC}"
            rm -f temp_client_ext.cnf temp_${TYPE}_key.pem temp_${TYPE}_req.pem temp_${TYPE}_cert.pem
            return 1
        fi
        
        rm -f temp_client_ext.cnf
    fi

    # Convert to PKCS12 format
    echo -e "${GREEN}Converting to PKCS12 format...${NC}"
    openssl pkcs12 -export -in temp_${TYPE}_cert.pem \
        -inkey temp_${TYPE}_key.pem \
        -certfile "$CA_CERT" \
        -out temp_${TYPE}.p12 \
        -name "$KEY_ALIAS" \
        -passout pass:$KEYSTORE_PASSWORD

    # Check if PKCS12 conversion was successful
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to convert to PKCS12 format for ${TYPE}${NC}"
        rm -f temp_${TYPE}_cert.pem temp_${TYPE}_key.pem temp_${TYPE}_req.pem
        return 1
    fi

    # Import PKCS12 into Java keystore
    echo -e "${GREEN}Creating ${TYPE} keystore...${NC}"
    keytool -importkeystore \
        -srckeystore temp_${TYPE}.p12 \
        -srcstoretype PKCS12 \
        -srcstorepass "$KEYSTORE_PASSWORD" \
        -destkeystore "$KEYSTORE_NAME" \
        -deststoretype JKS \
        -deststorepass "$KEYSTORE_PASSWORD" \
        -alias "$KEY_ALIAS"

    # Check if keystore import was successful
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to import into Java keystore for ${TYPE}${NC}"
        rm -f temp_${TYPE}_cert.pem temp_${TYPE}_key.pem temp_${TYPE}.p12 temp_${TYPE}_req.pem
        return 1
    fi

    # Check if the keystore was created successfully
    if [ -f "$KEYSTORE_NAME" ]; then
        # Capitalize TYPE for display (bash 3.2 compatible)
        TYPE_DISPLAY="$(echo "${TYPE:0:1}" | tr '[:lower:]' '[:upper:]')${TYPE:1}"
        echo -e "${GREEN}✓ ${TYPE_DISPLAY} keystore created successfully: $KEYSTORE_NAME${NC}"
        echo ""
        echo "Keystore details:"
        echo "  Type: ${TYPE_DISPLAY}"
        echo "  File: $KEYSTORE_NAME"
        echo "  Password: $KEYSTORE_PASSWORD"
        echo "  Alias: $KEY_ALIAS"
        echo "  Validity: $VALIDITY_DAYS days"
        echo "  Subject: $CERT_SUBJECT"
        echo "  Signed by CA: $CA_CERT"
        if [ "$TYPE" = "client" ] && [ "$SINGLE_USE" = true ]; then
            echo "  Mode: Single-use (serverAuth EKU)"
        fi
        echo ""
        
        # List the contents of the keystore
        echo -e "${GREEN}Keystore contents:${NC}"
        keytool -list -keystore "$KEYSTORE_NAME" -storepass "$KEYSTORE_PASSWORD"
        
        # Clean up temporary files
        rm -f temp_${TYPE}_cert.pem temp_${TYPE}_key.pem temp_${TYPE}.p12 temp_${TYPE}_req.pem
        
        echo ""
        return 0
    else
        echo -e "${RED}✗ Failed to create ${TYPE} keystore${NC}"
        # Clean up temporary files on failure
        rm -f temp_${TYPE}_cert.pem temp_${TYPE}_key.pem temp_${TYPE}.p12 temp_${TYPE}_req.pem
        return 1
    fi
}

# Function to create truststore
create_truststore() {
    local TRUSTSTORE_NAME="truststore.jks"
    
    echo -e "${GREEN}Creating truststore: ${TRUSTSTORE_NAME}${NC}"
    echo "=============================================="
    
    # Remove existing truststore if it exists
    if [ -f "$TRUSTSTORE_NAME" ]; then
        echo -e "${YELLOW}Warning: $TRUSTSTORE_NAME already exists. Removing it...${NC}"
        rm "$TRUSTSTORE_NAME"
    fi
    
    # Import CA certificate into truststore
    keytool -import -alias ca -file "$CA_CERT" \
        -keystore "$TRUSTSTORE_NAME" \
        -storepass "$KEYSTORE_PASSWORD" \
        -noprompt
    
    # Check if truststore creation was successful
    if [ $? -eq 0 ] && [ -f "$TRUSTSTORE_NAME" ]; then
        echo -e "${GREEN}✓ Truststore created successfully: $TRUSTSTORE_NAME${NC}"
        echo ""
        echo "Truststore details:"
        echo "  File: $TRUSTSTORE_NAME"
        echo "  Password: $KEYSTORE_PASSWORD"
        echo "  Contains: CA certificate"
        echo ""
        
        # List the contents of the truststore
        echo -e "${GREEN}Truststore contents:${NC}"
        keytool -list -keystore "$TRUSTSTORE_NAME" -storepass "$KEYSTORE_PASSWORD"
        echo ""
        return 0
    else
        echo -e "${RED}✗ Failed to create truststore${NC}"
        return 1
    fi
}

# Main execution
echo -e "${GREEN}mTLS Keystore Creation Script${NC}"
echo "=============================="

# Check if keytool is available
if ! command -v keytool &> /dev/null; then
    echo -e "${RED}Error: keytool not found. Please ensure Java is installed and JAVA_HOME is set.${NC}"
    exit 1
fi

# Check if openssl is available
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: openssl not found. Please install OpenSSL.${NC}"
    exit 1
fi

# Check if CA certificate and key files exist
if [ ! -f "$CA_CERT" ]; then
    echo -e "${RED}Error: CA certificate file not found: $CA_CERT${NC}"
    exit 1
fi

if [ ! -f "$CA_KEY" ]; then
    echo -e "${RED}Error: CA private key file not found: $CA_KEY${NC}"
    exit 1
fi

# Execute based on keystore type
if [ "$KEYSTORE_TYPE" = "all" ]; then
    echo -e "${GREEN}Creating complete mTLS setup (client + server + truststore)${NC}"
    echo ""
    
    # Create server keystore
    if ! create_keystore "server"; then
        echo -e "${RED}Failed to create server keystore. Aborting.${NC}"
        exit 1
    fi
    
    # Create client keystore
    if ! create_keystore "client"; then
        echo -e "${RED}Failed to create client keystore. Aborting.${NC}"
        exit 1
    fi
    
    # Create truststore
    if ! create_truststore; then
        echo -e "${RED}Failed to create truststore. Aborting.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Complete mTLS setup created successfully!${NC}"
    echo ""
    echo "Created files:"
    echo "  - server.jks (server private key and certificate)"
    echo "  - client.jks (client private key and certificate)"
    echo "  - truststore.jks (CA certificate for trust validation)"
    echo ""
    echo -e "${YELLOW}Note: All certificates are signed by the CA certificate: $CA_CERT${NC}"
    echo -e "${YELLOW}For production, ensure your CA certificate is trusted.${NC}"
    
elif [ "$KEYSTORE_TYPE" = "server" ]; then
    if ! create_keystore "server"; then
        echo -e "${RED}Failed to create server keystore.${NC}"
        exit 1
    fi
    echo -e "${YELLOW}Note: This certificate is signed by the CA certificate: $CA_CERT${NC}"
    echo -e "${YELLOW}For production, ensure your CA certificate is trusted.${NC}"
    
elif [ "$KEYSTORE_TYPE" = "client" ]; then
    if ! create_keystore "client"; then
        echo -e "${RED}Failed to create client keystore.${NC}"
        exit 1
    fi
    echo -e "${YELLOW}Note: This certificate is signed by the CA certificate: $CA_CERT${NC}"
    echo -e "${YELLOW}For production, ensure your CA certificate is trusted.${NC}"
fi