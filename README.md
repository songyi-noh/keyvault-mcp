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

**1단계: 프로젝트 클론**
```powershell
git clone https://github.com/songyi-noh/azure-keyvault-mcp.git
cd azure-keyvault-mcp
```

**2단계: venv 생성 (프로젝트 폴더 안에 생성됨)**
```powershell
python -m venv venv
```

> 이 명령을 실행하면 `azure-keyvault-mcp\venv\` 폴더가 생성됩니다.

**3단계: venv 활성화**
```powershell
venv\Scripts\activate
```

> 활성화되면 프롬프트 앞에 `(venv)`가 표시됩니다.

**4단계: 필요한 패키지 설치**
```powershell
pip install -r requirements.txt
```

**5단계: Azure 로그인**
```powershell
az login
```

> **참고:** 
> - Windows에서 Python이 설치되어 있지 않다면 [Python 공식 사이트](https://www.python.org/downloads/)에서 다운로드하세요.
> - Python 설치 시 "Add Python to PATH" 옵션을 체크하는 것을 권장합니다.
> - `python` 명령이 작동하지 않으면 `py` 명령을 시도해보세요.

## ⚙️ MCP 서버 설정

> **💡 venv란?**
> 
> `venv`는 **프로젝트 폴더 안에 생성되는 가상환경**입니다.
> 
> - **생성 위치:** 프로젝트 폴더 안의 `venv/` 디렉토리
> - **생성 방법:** `python3 -m venv venv` 명령으로 생성
> - **Python 경로:**
>   - macOS/Linux: `프로젝트경로/venv/bin/python`
>   - Windows: `프로젝트경로\venv\Scripts\python.exe`
> - **왜 사용하나요?** 프로젝트별로 독립적인 Python 패키지 환경을 만들어 의존성 충돌을 방지합니다
> 
> MCP 설정에서 이 venv의 Python을 사용하여 `server.py`를 실행합니다.

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

> **💡 프로젝트별 규칙 설정:**
> 
> Cursor의 `.cursorrules`와 비슷하게, Claude Desktop에서도 프로젝트별 규칙을 설정할 수 있습니다:
> - 프로젝트 루트에 `.claude` 파일을 생성하면 Claude Desktop이 자동으로 인식합니다
> - `.cursorrules` 파일과 동일한 내용을 `.claude` 파일로 복사하여 사용할 수 있습니다

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

### ⚠️ Windows에서 "지정된 경로를 찾을 수 없다" 오류 해결

**문제 진단:**

1. **Python 실행 파일 경로 확인:**
   ```powershell
   # 프로젝트 폴더에서 실행
   cd C:\Users\YourName\azure-keyvault-mcp
   
   # venv의 Python이 존재하는지 확인
   Test-Path venv\Scripts\python.exe
   # True가 나와야 함
   ```

2. **server.py 파일 경로 확인:**
   ```powershell
   Test-Path server.py
   # True가 나와야 함
   ```

3. **경로에 공백이나 특수문자가 있는지 확인:**
   - 경로에 공백이 있으면 따옴표로 감싸야 할 수 있습니다
   - 예: `C:\Users\My Name\azure-keyvault-mcp` → 경로에 공백 있음

**해결 방법:**

1. **슬래시 사용 (권장):**
   ```json
   {
     "mcpServers": {
       "azure-keyvault": {
         "command": "C:/Users/YourName/azure-keyvault-mcp/venv/Scripts/python.exe",
         "args": ["C:/Users/YourName/azure-keyvault-mcp/server.py"]
       }
     }
   }
   ```
   > Windows에서도 슬래시(`/`)를 사용할 수 있습니다!

2. **경로에 공백이 있는 경우:**
   ```json
   {
     "mcpServers": {
       "azure-keyvault": {
         "command": "\"C:/Users/My Name/azure-keyvault-mcp/venv/Scripts/python.exe\"",
         "args": ["C:/Users/My Name/azure-keyvault-mcp/server.py"]
       }
     }
   }
   ```

3. **venv가 제대로 생성되었는지 확인:**
   ```powershell
   # venv 재생성
   Remove-Item -Recurse -Force venv
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```

4. **절대 경로 대신 상대 경로 사용 (프로젝트 폴더 기준):**
   ```json
   {
     "mcpServers": {
       "azure-keyvault": {
         "command": "python",
         "args": ["-m", "venv", "venv", "&&", "venv\\Scripts\\python.exe", "server.py"]
       }
     }
   }
   ```
   > 이 방법은 작동하지 않을 수 있으므로 **절대 경로 사용을 권장**합니다.

**가장 확실한 방법:**

PowerShell에서 다음 명령으로 정확한 경로를 복사하세요:
```powershell
cd C:\Users\YourName\azure-keyvault-mcp
$pythonPath = (Resolve-Path "venv\Scripts\python.exe").Path
$serverPath = (Resolve-Path "server.py").Path
Write-Host "Python: $pythonPath"
Write-Host "Server: $serverPath"
```

출력된 경로를 그대로 설정 파일에 복사하되, 백슬래시를 슬래시로 변경하거나 `\\`로 이스케이프하세요.

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

