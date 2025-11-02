"""
Google Gemini AI analyzer for vulnerability scan results.
"""
import json
import os
import time
from typing import Dict, Any, List
import google.generativeai as genai
from datetime import datetime
from .api_setup import APISetup


class GeminiAnalyzer:
    """Google Gemini analyzer for comprehensive security analysis."""
    
    def __init__(self, model: str = "gemini-2.5-flash"):
        self.model_name = model
        self.client = None
        self.setup = APISetup()
        self._initialized = False
    
    def initialize(self) -> bool:
        """Initialize the analyzer with user-friendly setup."""
        if self._initialized:
            return True
            
        print("\n🤖 INITIALIZING AI ANALYSIS...")
        
        if not self.setup.setup_api_key():
            return False
        
        try:
            # Use the key from setup directly
            if not self.setup.api_key:
                print("❌ No API key available")
                return False
                
            genai.configure(api_key=self.setup.api_key)
            
            # Try the requested model
            try:
                self.client = genai.GenerativeModel(self.model_name)
                # Test with a quick request
                test_response = self.client.generate_content("test", request_options={"timeout": 10})
                self._initialized = True
                print(f"✅ Google Gemini configured: {self.model_name}")
                return True
            except Exception as model_error:
                print(f"❌ Model {self.model_name} failed: {model_error}")
                
                # Try fallback to gemini-2.5-flash
                if self.model_name != "gemini-2.5-flash":
                    print("🔄 Trying fallback to gemini-2.5-flash...")
                    try:
                        self.client = genai.GenerativeModel("gemini-2.5-flash")
                        self.model_name = "gemini-2.5-flash"
                        self._initialized = True
                        print("✅ Fallback to gemini-2.5-flash successful!")
                        return True
                    except Exception as fallback_error:
                        print(f"❌ Fallback also failed: {fallback_error}")
                
                return False
                
        except Exception as e:
            print(f"❌ Failed to initialize AI: {e}")
            return False
    
    def analyze_scan_results(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive AI analysis of vulnerability scan results."""
        if not self.initialize():
            return self._fallback_analysis(report_data)
        
        try:
            prompt = self._create_security_analysis_prompt(report_data)
            self.setup._show_animation("AI analyzing results", 3)
            
            response = self.client.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.3,
                    top_p=0.8,
                    top_k=40,
                    max_output_tokens=2048,
                )
            )
            
            return self._parse_gemini_response(response.text, report_data)
            
        except Exception as e:
            print(f"❌ Gemini analysis failed: {e}")
            return self._fallback_analysis(report_data)
    
    def _create_security_analysis_prompt(self, report_data: Dict[str, Any]) -> str:
        """Create optimized prompt for security vulnerability analysis."""
        target = report_data.get('scan_metadata', {}).get('target', 'Unknown')
        vulnerabilities = report_data.get('vulnerabilities', [])
        
        severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        critical_vulns = []
        high_vulns = []
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity in severity_count:
                severity_count[severity] += 1
            
            if severity == 'Critical':
                critical_vulns.append(vuln)
            elif severity == 'High':
                high_vulns.append(vuln)
        
        vuln_types = {}
        for vuln in vulnerabilities:
            v_type = vuln.get('type', 'Unknown')
            vuln_types[v_type] = vuln_types.get(v_type, 0) + 1
        
        prompt = f"""
You are a senior cybersecurity analyst with 15 years of experience.

**TASK:** Analyze these web vulnerability scan results and provide a comprehensive security assessment.

**SCAN TARGET:** {target}
**SCAN OVERVIEW:**
- Total Vulnerabilities: {len(vulnerabilities)}
- Critical: {severity_count['Critical']}
- High: {severity_count['High']} 
- Medium: {severity_count['Medium']}
- Low: {severity_count['Low']}

**VULNERABILITY DISTRIBUTION:**
{json.dumps(vuln_types, indent=2)}

**CRITICAL FINDINGS ({len(critical_vulns)}):**
{self._format_vulnerabilities(critical_vulns)}

**HIGH SEVERITY FINDINGS ({len(high_vulns)}):**
{self._format_vulnerabilities(high_vulns)}

---

**REQUIRED ANALYSIS FORMAT (JSON):**

{{
  "executive_summary": "Brief overview for management (max 100 words)",
  "risk_assessment": {{
    "overall_risk_level": "Critical/High/Medium/Low",
    "business_impact": "Description of potential business consequences",
    "exploitation_likelihood": "High/Medium/Low",
    "urgency_level": "Immediate/High/Medium/Low"
  }},
  "critical_actions": [
    {{
      "action": "Specific remediation step",
      "priority": "P0/P1/P2",
      "timeline": "Immediate/24h/1 week",
      "effort": "Low/Medium/High"
    }}
  ],
  "technical_analysis": {{
    "root_causes": ["Primary technical root causes"],
    "patterns_identified": ["Recurring security anti-patterns"]
  }},
  "remediation_roadmap": [
    {{
      "phase": "Immediate (0-24 hours)",
      "actions": ["Action 1", "Action 2"]
    }},
    {{
      "phase": "Short-term (1-2 weeks)", 
      "actions": ["Action 1", "Action 2"]
    }}
  ]
}}

Provide ONLY valid JSON output, no additional text.
"""

        return prompt
    
    def _format_vulnerabilities(self, vulnerabilities: List[Dict]) -> str:
        """Format vulnerabilities for the prompt."""
        if not vulnerabilities:
            return "None"
        
        formatted = []
        for i, vuln in enumerate(vulnerabilities[:5], 1):
            formatted.append(
                f"{i}. {vuln.get('type')} at {vuln.get('url')}\n"
                f"   Evidence: {vuln.get('evidence', '')[:100]}...\n"
                f"   Remediation: {vuln.get('remediation', '').split('.')[0]}"
            )
        
        return "\n".join(formatted)
    
    def _parse_gemini_response(self, response_text: str, original_report: Dict) -> Dict[str, Any]:
        """Parse Gemini response into structured format."""
        try:
            clean_text = response_text.strip()
            if "```json" in clean_text:
                clean_text = clean_text.split("```json")[1].split("```")[0].strip()
            elif "```" in clean_text:
                clean_text = clean_text.split("```")[1].split("```")[0].strip()
            
            ai_analysis = json.loads(clean_text)
            
            return {
                "ai_analysis": ai_analysis,
                "metadata": {
                    "analyzer": "Google Gemini",
                    "model": self.model_name,
                    "analysis_timestamp": datetime.now().isoformat(),
                    "original_findings_count": len(original_report.get('vulnerabilities', [])),
                    "target": original_report.get('scan_metadata', {}).get('target')
                },
                "success": True
            }
            
        except json.JSONDecodeError as e:
            return {
                "ai_analysis": {
                    "raw_response": response_text,
                    "error": "Response could not be parsed as JSON"
                },
                "metadata": {
                    "analyzer": "Google Gemini",
                    "model": self.model_name,
                    "analysis_timestamp": datetime.now().isoformat()
                },
                "success": False
            }
    
    def _fallback_analysis(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Provide basic analysis when AI is unavailable."""
        vulnerabilities = report_data.get('vulnerabilities', [])
        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
        high_count = len([v for v in vulnerabilities if v.get('severity') == 'High'])
        
        if critical_count > 0:
            risk_level = "CRITICAL"
            urgency = "IMMEDIATE"
        elif high_count > 0:
            risk_level = "HIGH" 
            urgency = "HIGH"
        else:
            risk_level = "MEDIUM"
            urgency = "MEDIUM"
        
        return {
            "ai_analysis": {
                "executive_summary": f"Automated analysis: {len(vulnerabilities)} vulnerabilities found. {critical_count} critical, {high_count} high severity.",
                "risk_assessment": {
                    "overall_risk_level": risk_level,
                    "urgency_level": urgency
                },
                "critical_actions": [
                    {
                        "action": "Review critical vulnerabilities immediately",
                        "priority": "P0" if critical_count > 0 else "P1",
                        "timeline": "Immediate" if critical_count > 0 else "24 hours",
                        "effort": "High"
                    }
                ]
            },
            "metadata": {
                "analyzer": "Fallback Analysis",
                "analysis_timestamp": datetime.now().isoformat(),
                "note": "AI analysis unavailable - using rule-based fallback"
            },
            "success": False
        }