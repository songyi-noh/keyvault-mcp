#!/bin/bash
# 테스트용 인증서 생성 스크립트
# 사용법: ./generate_test_certs.sh [출력 디렉토리]

OUTPUT_DIR="${1:-./test-certs}"
mkdir -p "$OUTPUT_DIR"

echo "🔐 테스트용 인증서 생성 중..."

# ===== 1. 루트 CA 인증서 생성 =====
echo "📝 루트 CA 인증서 생성..."
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$OUTPUT_DIR/root-ca.key" \
    -out "$OUTPUT_DIR/root-ca.crt" \
    -days 365 \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=Test CA/CN=Root CA" \
    -extensions v3_ca

# ===== 2. 중간 CA 인증서 생성 =====
echo "📝 중간 CA 인증서 생성..."

# 중간 CA 개인키 생성
openssl genrsa -out "$OUTPUT_DIR/intermediate-ca.key" 2048

# 중간 CA CSR 생성
openssl req -new -key "$OUTPUT_DIR/intermediate-ca.key" \
    -out "$OUTPUT_DIR/intermediate-ca.csr" \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=Test Intermediate CA/CN=Intermediate CA"

# 루트 CA로 중간 CA 서명
openssl x509 -req -in "$OUTPUT_DIR/intermediate-ca.csr" \
    -CA "$OUTPUT_DIR/root-ca.crt" \
    -CAkey "$OUTPUT_DIR/root-ca.key" \
    -CAcreateserial \
    -out "$OUTPUT_DIR/intermediate-ca.crt" \
    -days 365 \
    -extensions v3_intermediate_ca \
    -extfile <(cat <<EOF
[v3_intermediate_ca]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical, keyCertSign, cRLSign
EOF
)

# ===== 3. 서버 인증서 생성 =====
echo "📝 서버 인증서 생성..."

# 서버 개인키 생성
openssl genrsa -out "$OUTPUT_DIR/server.key" 2048

# 서버 CSR 생성
openssl req -new -key "$OUTPUT_DIR/server.key" \
    -out "$OUTPUT_DIR/server.csr" \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=Test Server/CN=test.example.com"

# 중간 CA로 서버 인증서 서명
openssl x509 -req -in "$OUTPUT_DIR/server.csr" \
    -CA "$OUTPUT_DIR/intermediate-ca.crt" \
    -CAkey "$OUTPUT_DIR/intermediate-ca.key" \
    -CAcreateserial \
    -out "$OUTPUT_DIR/server.crt" \
    -days 365 \
    -extensions v3_server \
    -extfile <(cat <<EOF
[v3_server]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = test.example.com
DNS.2 = *.test.example.com
IP.1 = 127.0.0.1
EOF
)

# ===== 4. PEM 형식으로 변환 (체인 파일 생성) =====
echo "📝 체인 파일 생성..."

# 체인 파일 (서버 + 중간 CA)
cat "$OUTPUT_DIR/server.crt" "$OUTPUT_DIR/intermediate-ca.crt" > "$OUTPUT_DIR/server-chain.crt"

# 전체 체인 파일 (서버 + 중간 CA + 루트 CA)
cat "$OUTPUT_DIR/server.crt" "$OUTPUT_DIR/intermediate-ca.crt" "$OUTPUT_DIR/root-ca.crt" > "$OUTPUT_DIR/server-fullchain.crt"

# ===== 5. 정리 =====
rm -f "$OUTPUT_DIR/intermediate-ca.csr" "$OUTPUT_DIR/server.csr"
rm -f "$OUTPUT_DIR/root-ca.srl" "$OUTPUT_DIR/intermediate-ca.srl"

echo ""
echo "✅ 인증서 생성 완료!"
echo ""
echo "📁 생성된 파일:"
echo "  - $OUTPUT_DIR/server.crt          (서버 인증서)"
echo "  - $OUTPUT_DIR/server.key          (서버 개인키)"
echo "  - $OUTPUT_DIR/intermediate-ca.crt (중간 CA 인증서)"
echo "  - $OUTPUT_DIR/root-ca.crt         (루트 CA 인증서)"
echo "  - $OUTPUT_DIR/server-chain.crt    (서버 + 중간 CA)"
echo "  - $OUTPUT_DIR/server-fullchain.crt (전체 체인)"
echo ""
echo "🧪 테스트 방법:"
echo "  1. 체인 자동 감지 테스트:"
echo "     import_certificate_with_auto_chain("
echo "       name='test-cert',"
echo "       cert_path='$OUTPUT_DIR/server.crt',"
echo "       key_path='$OUTPUT_DIR/server.key'"
echo "     )"
echo ""
echo "  2. 체인 패턴 지정 테스트:"
echo "     import_certificate_with_auto_chain("
echo "       name='test-cert',"
echo "       cert_path='$OUTPUT_DIR/server.crt',"
echo "       key_path='$OUTPUT_DIR/server.key',"
echo "       chain_patterns=['intermediate*.crt']"
echo "     )"
echo ""

