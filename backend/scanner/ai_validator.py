"""AI Validation Module using OpenAI to reduce false positives and generate patches."""

import httpx
import json
from models import Finding

async def validate_findings_with_ai(findings: list[Finding], api_key: str) -> list[Finding]:
    """Passes findings to OpenAI to validate if they are false positives, and generates code patches."""
    if not api_key:
        return findings

    validated_findings = []
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        for finding in findings:
            try:
                prompt = f"""
                You are an expert Application Security Engineer. Review the following DAST finding.
                Your job is to determine if this is likely a FALSE POSITIVE or a REAL VULNERABILITY based on common patterns.
                Then, provide a concrete code snippet to fix this vulnerability in a modern web framework (like React/Next.js or Express/Django).
                
                Vulnerability: {finding.vulnerability_type}
                Severity: {finding.severity}
                URL: {finding.url}
                Description: {finding.description}
                
                Respond in JSON format only with the following keys:
                - is_false_positive (boolean)
                - confidence_score (0-100)
                - ai_recommendation (string, including the code patch)
                """

                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": prompt}],
                        "response_format": { "type": "json_object" },
                        "temperature": 0.1
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    content = data["choices"][0]["message"]["content"]
                    ai_result = json.loads(content)
                    
                    if not ai_result.get("is_false_positive", False):
                        # Append AI recommendation to the existing finding
                        finding.recommendation += f"\n\n**🤖 AI Code Patch & Analysis (Confidence: {ai_result.get('confidence_score', 0)}%)**\n{ai_result.get('ai_recommendation', '')}"
                        validated_findings.append(finding)
                else:
                    # If API fails, keep the original finding
                    validated_findings.append(finding)
                    
            except Exception as e:
                print(f"AI Validation failed for finding {finding.vulnerability_type}: {e}")
                validated_findings.append(finding)

    return validated_findings
