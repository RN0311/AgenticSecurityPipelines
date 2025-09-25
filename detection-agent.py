import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
import hashlib
import re

try:
    import ollama
    OLLAMA_AVAILABLE = True
    print("✅ Ollama package available")
except ImportError:
    OLLAMA_AVAILABLE = False
    print("❌ Ollama not installed. Run: pip install ollama")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VulnerabilityType(Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    BUFFER_OVERFLOW = "buffer_overflow"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_CRYPTO = "insecure_cryptography"
    AUTHENTICATION_BYPASS = "auth_bypass"
    COMMAND_INJECTION = "command_injection"
    INSECURE_DESERIALIZATION = "insecure_deserialization"

class SeverityLevel(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

@dataclass
class Vulnerability:
    id: str
    type: VulnerabilityType
    severity: SeverityLevel
    file_path: str
    line_number: int
    description: str
    code_snippet: str
    confidence_score: float
    detected_at: datetime

class VulnerabilityDetector:
    
    def __init__(self, model_name: str = "gpt-oss:20b"):
        self.model_name = model_name
        self.use_ollama = OLLAMA_AVAILABLE
        
        if self.use_ollama:
            self._check_model_availability()
        else:
            logger.warning("Ollama not available, using fallback detection")
    

    def _check_model_availability(self):
        try:
            models_response = ollama.list()
            logger.info(f"Ollama list response: {models_response}")
            
            if hasattr(models_response, 'models') and isinstance(models_response.models, list):
                model_list = models_response.models
            elif isinstance(models_response, list):
                model_list = models_response
            else:
                logger.error("Unexpected response format from ollama.list(). 'models' attribute not found or not a list.")
                self.use_ollama = False
                return

            available_models = []
            for model_obj in model_list:
                if hasattr(model_obj, 'model'):
                    available_models.append(model_obj.model)
                else:
                    logger.warning(f"Model object in list has no 'model' attribute: {model_obj}")
            
            logger.info(f"Parsed available models: {available_models}")
            

            model_found = any(self.model_name in model_name_str for model_name_str in available_models)
            
            if model_found:
                logger.info(f"✅ Using Ollama model: {self.model_name}")
            else:
                logger.warning(f"❌ Model '{self.model_name}' not found")
                logger.info(f"Available models: {available_models}")
                logger.info(f"To install: ollama pull {self.model_name}")
                self.use_ollama = False
                
        except Exception as e:
            logger.error(f"Failed to connect to Ollama: {e}")
            self.use_ollama = False
    

    async def analyze_code(self, file_path: str, code_content: str) -> List[Vulnerability]:
        logger.info(f"🔍 Analyzing {file_path}...")
        
        if self.use_ollama:
            try:
                vulnerabilities = await self._analyze_with_ollama(file_path, code_content)
                logger.info(f"✅ Vulnerability detection complete")
                return vulnerabilities
            except Exception as e:
                logger.error(f"Vulnerability detection failed: {e}")
                return []
        else:
            return await self._fallback_analysis(file_path, code_content)
    

    async def _analyze_with_ollama(self, file_path: str, code_content: str) -> List[Vulnerability]:
        
        prompt = self._create_analysis_prompt(file_path, code_content)
        
        logger.info(f"🤖 Sending code to Ollama model: {self.model_name}")
        
        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                options={
                    "temperature": 0.1,
                    "top_k": 10,
                    "top_p": 0.9
                }
            )
            
            response_text = response['message']['content']
            logger.info("📝 Received response from Ollama")
            print("\n" + "="*60)
            print("🤖 RAW LLM RESPONSE")
            print("="*60)
            print(response_text)
            print("="*60 + "\n")

            return []
            
        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            raise
    
    def _create_analysis_prompt(self, file_path: str, code_content: str) -> str:
        """Create a detailed prompt for vulnerability analysis"""
        
        prompt = f"""You are a cybersecurity expert analyzing code for vulnerabilities.

**Task**: Analyze the following code and identify ALL security vulnerabilities.

**File**: {file_path}
**Code**:
```
{code_content}
```

**Instructions**:
1. Look for common vulnerabilities like:
   - SQL Injection (string concatenation in database queries)
   - Cross-Site Scripting/XSS (unsafe HTML output)
   - Command Injection (unsafe system calls)
   - Path Traversal (unsafe file operations)
   - Insecure Cryptography (weak hashing, encryption)
   - Authentication Bypass (weak validation)
   - Insecure Deserialization

2. For EACH vulnerability found, respond with ONLY a JSON array in this EXACT format:

[
  {{
    "type": "sql_injection",
    "line_number": 5,
    "code_snippet": "query = 'SELECT * FROM users WHERE id=' + user_id",
    "explanation": "SQL injection vulnerability due to string concatenation",
    "confidence": 0.95
  }},
  {{
    "type": "xss",
    "line_number": 12,
    "code_snippet": "element.innerHTML = userInput",
    "explanation": "XSS vulnerability from unescaped user input in DOM",
    "confidence": 0.88
  }}
]

**Valid types**: sql_injection, xss, command_injection, path_traversal, insecure_crypto, auth_bypass, insecure_deserialization

**Important**: 
- If NO vulnerabilities found, return: []
- Only include ACTUAL vulnerabilities, not potential issues
- Provide exact line numbers where possible
- Include the vulnerable code snippet
- Give confidence score 0.0-1.0

**CRITICAL RULES**:
- OUTPUT MUST BE PURE JSON. NO MARKDOWN. NO EXPLANATIONS. NO THINKING STEPS.
- Escape all double quotes inside strings with backslash: \"
- Example: "code_snippet": "element.innerHTML = \\" + userInput + \\""

"""

        return prompt
    

    async def _parse_ollama_response(self, response_text: str, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        separator = "="*60
        print(f"\n{separator}")
        print("🤖 RAW LLM RESPONSE (FOR DEBUGGING)")
        print(separator)
        print(response_text)
        print(f"{separator}\n")

        try:
            json_match = re.search(r'\[\s*\{.*\}\s*(,\s*\{.*\}\s*)*\]', response_text, re.DOTALL)
            if json_match:
                json_text = json_match.group(0)
                logger.debug(f"Extracted JSON with regex: {json_text}")
            else:
                logger.warning("No JSON array found in response even with regex.")
                return vulnerabilities

            def escape_json_quotes(s):
                result = []
                in_string = False
                i = 0
                while i < len(s):
                    char = s[i]
                    if char == '"' and (i == 0 or s[i-1] != '\\'):
                        in_string = not in_string
                        result.append(char)
                    elif char == '"' and in_string:
                        result.append('\\"')
                    else:
                        result.append(char)
                    i += 1
                return ''.join(result)

            fixed_json = escape_json_quotes(json_text)

            vulns_data = json.loads(fixed_json)
            print(f"Parsed vulnerabilities: {vulns_data}")

            if not isinstance(vulns_data, list):
                logger.warning("Parsed JSON is not a list")
                return vulnerabilities

            for item in vulns_data:
                vuln = self._create_vulnerability_from_data(item, file_path)
                if vuln:
                    vulnerabilities.append(vuln)

            logger.info(f"✅ Parsed {len(vulnerabilities)} vulnerabilities from Ollama response")

        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing failed: {e}")
            logger.debug(f"Attempted to parse: {json_text[:500]}...")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")

        return vulnerabilities  


    def _create_vulnerability_from_data(self, vuln_data: dict, file_path: str) -> Optional[Vulnerability]:
        try:
            type_mapping = {
                "sql_injection": VulnerabilityType.SQL_INJECTION,
                "xss": VulnerabilityType.XSS,
                "cross_site_scripting": VulnerabilityType.XSS,
                "command_injection": VulnerabilityType.COMMAND_INJECTION,
                "path_traversal": VulnerabilityType.PATH_TRAVERSAL,
                "insecure_crypto": VulnerabilityType.INSECURE_CRYPTO,
                "auth_bypass": VulnerabilityType.AUTHENTICATION_BYPASS,
                "authentication_bypass": VulnerabilityType.AUTHENTICATION_BYPASS,
                "insecure_deserialization": VulnerabilityType.INSECURE_DESERIALIZATION
            }
            
            vuln_type_str = vuln_data.get('type', '').lower()
            vuln_type = type_mapping.get(vuln_type_str)
            
            if not vuln_type:
                logger.warning(f"Unknown vulnerability type: {vuln_type_str}")
                return None
            
            raw_line_number = vuln_data.get('line_number', 0)
            if isinstance(raw_line_number, list):
                if raw_line_number:
                    line_number = int(raw_line_number[0])
                else:
                    line_number = 0
                logger.warning(f"Line number received as list, using first element: {raw_line_number} -> {line_number}")
            else:
                line_number = int(raw_line_number) 

            raw_code_snippet = vuln_data.get('code_snippet', '')
            if isinstance(raw_code_snippet, list):
                code_snippet = "\n".join(raw_code_snippet) 
                logger.warning(f"Code snippet received as list, joining them: {raw_code_snippet} -> '{code_snippet}'")
            else:
                code_snippet = str(raw_code_snippet)
            
            vulnerability = Vulnerability(
                id=self._generate_vuln_id(file_path, line_number), 
                type=vuln_type,
                severity=self._assess_severity(vuln_type),
                file_path=file_path,
                line_number=line_number, 
                description=vuln_data.get('explanation', 'Vulnerability detected by Ollama'),
                code_snippet=code_snippet, 
                confidence_score=vuln_data.get('confidence', 0.8),
                detected_at=datetime.now()
            )
            
            return vulnerability
            
        except Exception as e:
            logger.error(f"Error creating vulnerability object from data {vuln_data}: {e}") 
            return None
    
    async def _fallback_analysis(self, file_path: str, code_content: str) -> List[Vulnerability]:
        logger.info("🔄 Using fallback pattern analysis")
        
        vulnerabilities = []
        lines = code_content.split('\n')
        patterns = {
            VulnerabilityType.SQL_INJECTION: [r"SELECT.*\+.*", r"INSERT.*\+.*", r"UPDATE.*\+.*", r"DELETE.*\+.*"],
            VulnerabilityType.XSS: [r"innerHTML\s*=", r"document\.write", r"\.html\("],
            VulnerabilityType.INSECURE_CRYPTO: [r"md5\(", r"sha1\("]
        }
        import re
        from datetime import datetime
        for line_num, line in enumerate(lines, 1):
            for vuln_type, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            id=self._generate_vuln_id(file_path, line_num),
                            type=vuln_type,
                            severity=self._assess_severity(vuln_type),
                            file_path=file_path,
                            line_number=line_num,
                            description=f"Potential {vuln_type.value} detected by pattern matching",
                            code_snippet=line.strip(),
                            confidence_score=0.6,
                            detected_at=datetime.now()
                        ))
                        break  
        return vulnerabilities
    
    def _generate_vuln_id(self, file_path: str, line_num: int) -> str:
        return hashlib.md5(f"{file_path}:{line_num}:{datetime.now().isoformat()}".encode()).hexdigest()[:8]
    
    def _assess_severity(self, vuln_type: VulnerabilityType) -> SeverityLevel:
        severity_map = {
            VulnerabilityType.SQL_INJECTION: SeverityLevel.CRITICAL,
            VulnerabilityType.COMMAND_INJECTION: SeverityLevel.CRITICAL,
            VulnerabilityType.XSS: SeverityLevel.HIGH,
            VulnerabilityType.PATH_TRAVERSAL: SeverityLevel.HIGH,
            VulnerabilityType.AUTHENTICATION_BYPASS: SeverityLevel.CRITICAL,
            VulnerabilityType.INSECURE_DESERIALIZATION: SeverityLevel.HIGH,
            VulnerabilityType.INSECURE_CRYPTO: SeverityLevel.MEDIUM,
        }
        return severity_map.get(vuln_type, SeverityLevel.LOW)

async def demo_vulnerability_detection():
    vulnerable_code = """
def login(username, password):
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()

def display_user_content(user_input):
    # XSS vulnerability  
    document.getElementById("content").innerHTML = user_input
    
def hash_password(password):
    # Weak cryptography
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()

def execute_command(user_command):
    # Command injection vulnerability
    import os
    os.system("ls " + user_command)

def load_user_file(filename):
    # Path traversal vulnerability
    with open("/uploads/" + filename, 'r') as f:
        return f.read()
"""

    #print("🚀 VULNERABILITY DETECTION DEMO")
    print("=" * 50)
    

    detector = VulnerabilityDetector(model_name="gpt-oss:20b") 
    vulnerabilities = await detector.analyze_code("vulnerable_app.py", vulnerable_code)
    

def setup_instructions():
    print("\n🔧 SETUP INSTRUCTIONS:")
    print("=" * 30)
    print("1. Install Ollama:")
    print("   pip install ollama")
    print()
    print("2. Pull a model (choose one):")
    print("   ollama pull gpt-oss:20b   # Lightweight, good for code")
    print("   ollama pull codellama     # Code-specialized")
    print("   ollama pull mistral       # General purpose")
    print("   ollama pull qwen2.5-coder # Code-focused")
    print()
    print("3. Run this script:")
    print("   python vulnerability_detector.py")

if __name__ == "__main__":
    if not OLLAMA_AVAILABLE:
        print("❌ Ollama package not found!")
        setup_instructions()
    else:
        asyncio.run(demo_vulnerability_detection())