"""
JWT Tampering vulnerability scanner module.
"""
from typing import Dict, Any, List
import jwt
import time
from utils import log_message, display_task_start, display_task_complete


def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for JWT vulnerabilities.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = test_jwt_tampering(target, options, ctx)
    return findings


def test_jwt_tampering(url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test for JWT vulnerabilities with detailed evidence."""
    display_task_start("JWT Testing")
    findings = []
    
    # Check if there are JWTs in cookies
    for cookie_name, cookie_value in ctx.session.cookies.items():
        if cookie_name.lower() in ['jwt', 'token', 'access_token', 'id_token', 'session']:
            try:
                # Try to decode the JWT without verification
                decoded = jwt.decode(cookie_value, options={"verify_signature": False})
                headers = jwt.get_unverified_header(cookie_value)
                
                evidence_found = None
                impact_description = ""
                vulnerability_type = ""
                
                # Test for alg:none vulnerability
                if headers.get('alg', '').upper() == 'NONE':
                    evidence_found = f"JWT accepts 'none' algorithm"
                    impact_description = "Signature verification can be bypassed"
                    vulnerability_type = "algorithm confusion"
                    
                    finding = {
                        "type": "JWT Algorithm Vulnerability",
                        "severity": "High",
                        "url": url,
                        "evidence": f"{evidence_found} for token '{cookie_name}'. {impact_description}. Attackers can forge tokens without valid signatures.",
                        "description": "The JWT token accepts the 'none' algorithm, which can be exploited to bypass signature verification and forge arbitrary tokens.",
                        "remediation": "Always validate JWT signatures and reject tokens with 'none' algorithm. Use strong cryptographic algorithms like RS256. Implement proper JWT library configuration.",
                        "request_data": f"Cookie: {cookie_name}={cookie_value[:50]}...",
                        "response_preview": f"JWT headers: {headers}",
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    findings.append(finding)
                    ctx.record_vulnerability(finding)
                
                # Test for weak secret (try common secrets)
                common_secrets = ['secret', 'password', '123456', 'qwerty', 'admin', 'key', 'token']
                for secret in common_secrets:
                    try:
                        jwt.decode(cookie_value, secret, algorithms=['HS256'])
                        evidence_found = f"JWT uses weak secret"
                        impact_description = f"Secret '{secret}' easily guessable"
                        vulnerability_type = "weak secret"
                        
                        finding = {
                            "type": "JWT Weak Secret Vulnerability", 
                            "severity": "High",
                            "url": url,
                            "evidence": f"{evidence_found} for token '{cookie_name}'. {impact_description}. Tokens can be forged with brute force attacks.",
                            "description": "The JWT token uses a weak secret that can be easily guessed, allowing attackers to forge valid tokens and impersonate users.",
                            "remediation": "Use strong, randomly generated secrets for JWT signing. Implement key rotation policies. Use asymmetric cryptography (RS256) instead of symmetric (HS256).",
                            "request_data": f"Cookie: {cookie_name}={cookie_value[:50]}... | Secret: {secret}",
                            "response_preview": f"JWT decoded with weak secret: {secret}",
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        }
                        findings.append(finding)
                        ctx.record_vulnerability(finding)
                        break
                    except jwt.InvalidSignatureError:
                        continue
                
                # Test for expired token acceptance
                if 'exp' in decoded:
                    import datetime
                    if decoded['exp'] < time.time():
                        evidence_found = f"Expired JWT token accepted"
                        impact_description = "Token expiration not enforced"
                        vulnerability_type = "expiration bypass"
                        
                        finding = {
                            "type": "JWT Expiration Vulnerability",
                            "severity": "Medium", 
                            "url": url,
                            "evidence": f"{evidence_found} for token '{cookie_name}'. {impact_description}. Expired tokens remain valid indefinitely.",
                            "description": "The application accepts expired JWT tokens, allowing continued access after token expiration periods.",
                            "remediation": "Always validate token expiration (exp claim). Implement proper token refresh mechanisms. Set reasonable token lifetimes.",
                            "request_data": f"Cookie: {cookie_name} (expired)",
                            "response_preview": f"Token expired at: {datetime.datetime.fromtimestamp(decoded['exp'])}",
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        }
                        findings.append(finding)
                        ctx.record_vulnerability(finding)
                        
            except jwt.DecodeError:
                # Not a JWT token
                continue
            except Exception as e:
                log_message(f"Error testing JWT {cookie_name}: {e}")
    
    display_task_complete("JWT Testing")
    return findings