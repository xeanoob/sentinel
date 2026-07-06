from fastapi import APIRouter
from store import scan_store

router = APIRouter(prefix="/api/v1")

@router.get("/analytics")
async def get_analytics():
    history = scan_store.load_history()
    
    total_scans = len(history)
    total_findings = 0
    severity_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    top_vulnerabilities = {}
    
    for scan in history:
        findings = scan.get("findings", [])
        total_findings += len(findings)
        
        for f in findings:
            sev = f.get("severity", "Low")
            vuln_type = f.get("vulnerability_type", "Unknown")
            
            if sev in severity_distribution:
                severity_distribution[sev] += 1
                
            top_vulnerabilities[vuln_type] = top_vulnerabilities.get(vuln_type, 0) + 1
            
    # Sort top vulnerabilities
    sorted_vulns = sorted(top_vulnerabilities.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "severity_distribution": severity_distribution,
        "top_vulnerabilities": [{"name": k, "count": v} for k, v in sorted_vulns],
        # Return the last 10 scans for the timeline trend
        "recent_scans": [
            {
                "date": s.get("start_time"), 
                "findings": sum(s.get("severity_counts", {}).values()) if s.get("severity_counts") else len(s.get("findings", []))
            } 
            for s in history[:10]
        ][::-1] # Reverse to get chronological order for the chart
    }
