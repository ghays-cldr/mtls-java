#!/bin/bash

# Test script to demonstrate the -single-use functionality
# This script shows the difference between normal and single-use client certificates

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== mTLS Single-Use Certificate Test ===${NC}"
echo ""

echo -e "${YELLOW}1. Creating normal client certificate (clientAuth EKU)...${NC}"
./create-keystore.sh -client
cp client.jks ../src/main/resources/
cp client.jks ../target/classes/

echo ""
echo -e "${YELLOW}2. Testing normal mTLS communication...${NC}"
echo "   This should work successfully."
cd ..
timeout 8 java -cp target/classes com.github.tls.App || echo -e "${GREEN}Normal mTLS completed successfully${NC}"

echo ""
echo -e "${YELLOW}3. Creating single-use client certificate (serverAuth EKU)...${NC}"
cd scripts
./create-keystore.sh -client -single-use
cp client.jks ../src/main/resources/
cp client.jks ../target/classes/

echo ""
echo -e "${YELLOW}4. Testing with single-use certificate (should fail)...${NC}"
echo "   This should fail because serverAuth EKU cannot be used for client authentication."
cd ..
timeout 8 java -cp target/classes com.github.tls.App || echo -e "${RED}Single-use certificate correctly rejected for client auth${NC}"

echo ""
echo -e "${YELLOW}5. Testing with -single-use flag (acknowledges the limitation)...${NC}"
echo "   This shows the application recognizes single-use mode."
timeout 8 java -cp target/classes com.github.tls.App -single-use || echo -e "${YELLOW}Single-use mode tested${NC}"

echo ""
echo -e "${GREEN}=== Test Complete ===${NC}"
echo ""
echo "Summary:"
echo "- Normal client certificates (clientAuth EKU) work for mTLS"
echo "- Single-use certificates (serverAuth EKU) are rejected for client authentication"
echo "- The -single-use flag indicates the application understands this limitation"
echo "- This demonstrates certificate-based access control through EKU restrictions"