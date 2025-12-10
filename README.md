# Azure Key Vault 관리 Agent (MCP)

**Azure Key Vault의 Secret 및 Certificate 관리 전문 MCP 서버**

## 🎯 이 Agent가 하는 일

### ✅ 전문 분야

- **Secret 관리**
  - Secret 등록/조회/목록/삭제
  - Secret 버전 관리

- **Certificate 관리**
  - 인증서 등록 (PFX, PEM, CRT 등 모든 형식 지원)
  - 인증서 형식 자동 변환 (PEM/CRT → PFX)
  - 인증서 체인 import
  - 인증서 조회/목록/삭제
  - 자체 서명 인증서 생성

- **인증 관리**
  - Azure CLI 인증 자동 체크
  - Key Vault 목록 조회 및 선택

### ❌ 이 Agent가 하지 않는 일

- App Service 배포
- Virtual Machine 관리
- 네트워크 설정
- Storage 관리
- 기타 Azure 리소스 관리

→ **Key Vault Secret/Certificate 관리만 전문**으로 다룹니다.

## 💬 사용 예시

### 인증서 교체

```
You: ssl 인증서 교체가 필요해

AI: 
✅ 인증 완료
📋 Key Vault 목록: 
1. kv-prod-01
2. kv-test-01

어느 Key Vault인가요? 

You: kv-prod-01

AI:
✅ kv-prod-01 선택됨
📋 현재 인증서:
1. ssl-cert-2024 (만료: 2025-06-30)
2. api-cert (만료: 2025-12-31)

어떤 인증서를 교체하시겠어요?

You: ssl-cert-2024

AI:
새 인증서 파일 형식이 무엇인가요?  (PFX/PEM/CRT)

You: PFX 파일 있어

AI:
PFX 파일을 base64로 인코딩해주세요: 
```bash
base64 -i new-cert.pfx | pbcopy
```
그리고 붙여넣어 주세요. 
비밀번호도 알려주세요.

You: [base64 내용], 비밀번호는 "pass123"

AI: 
✅ 인증서 'ssl-cert-2024' 교체 완료! 
Thumbprint: a1b2c3d4... 
만료일: 2026-12-31
```

### Secret 조회

```
You: db-password secret 값 알려줘

AI:
[자동으로 Key Vault 선택되어 있다면]
🔐 Secret 'db-password'
값: MySecretPassword123
버전: abc123
수정일: 2025-12-09
```

### 빠른 등록

```
You: kv-prod의 "api-key"로 "xyz789" secret 등록해줘

AI:
[select_keyvault 자동 실행]
[set_secret 자동 실행]
✅ Secret 'api-key' 저장 완료
버전: def456
```

## 📦 설치

### macOS/Linux

```bash
git clone https://github.com/songyi-noh/azure-keyvault-mcp.git
cd azure-keyvault-mcp
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
az login
```

### Windows

```powershell
git clone https://github.com/songyi-noh/azure-keyvault-mcp.git
cd azure-keyvault-mcp
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
az login
```

> **참고:** Windows에서 Python이 설치되어 있지 않다면 [Python 공식 사이트](https://www.python.org/downloads/)에서 다운로드하세요.

## ⚙️ MCP 서버 설정

### Cursor 설정

```json
// ~/.cursor/mcp.json
{
  "mcpServers": {
    "azure-keyvault": {
      "command": "/절대경로/azure-keyvault-mcp/venv/bin/python",
      "args": ["/절대경로/azure-keyvault-mcp/server.py"]
    }
  }
}
```

### Claude Desktop 설정

Claude Desktop에서도 이 MCP 서버를 사용할 수 있습니다.

**macOS:**
```json
// ~/Library/Application Support/Claude/claude_desktop_config.json
{
  "mcpServers": {
    "azure-keyvault": {
      "command": "/절대경로/azure-keyvault-mcp/venv/bin/python",
      "args": ["/절대경로/azure-keyvault-mcp/server.py"]
    }
  }
}
```

**Windows:**
```json
// %APPDATA%\Claude\claude_desktop_config.json
{
  "mcpServers": {
    "azure-keyvault": {
      "command": "C:\\절대경로\\azure-keyvault-mcp\\venv\\Scripts\\python.exe",
      "args": ["C:\\절대경로\\azure-keyvault-mcp\\server.py"]
    }
  }
}
```

> **💡 Windows에서 경로 찾는 방법:**
> 
> 1. **PowerShell에서 경로 확인:**
>    ```powershell
>    cd C:\Users\YourName\azure-keyvault-mcp
>    (Get-Location).Path
>    ```
> 
> 2. **또는 파일 탐색기에서:**
>    - 프로젝트 폴더를 열고 주소창을 클릭하면 전체 경로가 표시됩니다
>    - 예: `C:\Users\YourName\azure-keyvault-mcp`
> 
> 3. **설정 파일 예시 (실제 경로):**
>    ```json
>    {
>      "mcpServers": {
>        "azure-keyvault": {
>          "command": "C:\\Users\\YourName\\azure-keyvault-mcp\\venv\\Scripts\\python.exe",
>          "args": ["C:\\Users\\YourName\\azure-keyvault-mcp\\server.py"]
>        }
>      }
>    }
>    ```
> 
>    > **중요:** Windows 경로에서는 백슬래시(`\`)를 두 개(`\\`)로 이스케이프해야 합니다.

**Linux:**
```json
// ~/.config/Claude/claude_desktop_config.json
{
  "mcpServers": {
    "azure-keyvault": {
      "command": "/절대경로/azure-keyvault-mcp/venv/bin/python",
      "args": ["/절대경로/azure-keyvault-mcp/server.py"]
    }
  }
}
```

> **참고:** 설정 파일을 수정한 후 Claude Desktop을 재시작해야 합니다.

## 🛠️ 지원 도구

| 카테고리 | 도구 | 설명 |
|---------|------|------|
| **인증** | check_azure_auth | Azure 인증 상태 확인 |
| **Key Vault** | list_keyvaults | Key Vault 목록 조회 |
| | select_keyvault | Key Vault 선택 |
| **Secret** | set_secret | Secret 등록/업데이트 |
| | get_secret | Secret 조회 |
| | list_secrets | Secret 목록 |
| | delete_secret | Secret 삭제 |
| **Certificate** | import_certificate_from_pfx | PFX 인증서 import |
| | convert_pem_to_pfx_and_import | PEM → PFX 변환 후 import |
| | import_crt_certificate | CRT → PFX 변환 후 import |
| | import_bundle_certificate | 번들 PEM → PFX |
| | import_certificate_with_chain | 체인 포함 import |
| | generate_self_signed_cert | 자체 서명 인증서 생성 |
| | get_certificate | 인증서 조회 |
| | list_certificates | 인증서 목록 |
| | delete_certificate | 인증서 삭제 |
| | detect_certificate_format | 인증서 형식 감지 |
| | import_certificate_with_auto_chain | 파일 기반 인증서 import (체인 자동 감지) |

## 🧪 테스트용 인증서 생성

기능 테스트를 위해 가짜 인증서를 생성할 수 있습니다.

### 간단한 인증서 (체인 없음)

```bash
# 기본 사용 (test.example.com)
./generate_simple_cert.sh

# 커스텀 도메인 및 디렉토리
./generate_simple_cert.sh ./my-certs mydomain.com
```

생성되는 파일:
- `server.crt` - 서버 인증서
- `server.key` - 서버 개인키

### 체인 인증서 포함 (루트 CA + 중간 CA + 서버)

```bash
# 기본 사용 (./test-certs 디렉토리에 생성)
./generate_test_certs.sh

# 커스텀 디렉토리
./generate_test_certs.sh ./my-test-certs
```

생성되는 파일:
- `server.crt` / `server.key` - 서버 인증서 및 개인키
- `intermediate-ca.crt` - 중간 CA 인증서 (체인 테스트용)
- `root-ca.crt` - 루트 CA 인증서
- `server-chain.crt` - 서버 + 중간 CA 체인
- `server-fullchain.crt` - 전체 체인 (서버 + 중간 + 루트)

### 테스트 예시

```python
# 체인 자동 감지 테스트
# intermediate-ca.crt가 같은 디렉토리에 있으면 자동으로 감지됨
import_certificate_with_auto_chain(
    name="test-cert",
    cert_path="./test-certs/server.crt",
    key_path="./test-certs/server.key"
)

# 체인 패턴 지정 테스트
import_certificate_with_auto_chain(
    name="test-cert",
    cert_path="./test-certs/server.crt",
    key_path="./test-certs/server.key",
    chain_patterns=["intermediate*.crt", "chain*.pem"]
)
```

## 🤝 기여

Pull Request 환영합니다! 

**전문 분야:** Key Vault Secret/Certificate 관리에 집중

