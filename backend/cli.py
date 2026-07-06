#!/usr/bin/env python3
"""CLI interface for Sentinel DAST. Useful for CI/CD pipelines."""

import argparse
import asyncio
import json
import sys
import time
from urllib.parse import urlparse

import httpx


async def run_scan(target_url: str, api_mode: bool, fuzz_mode: bool, fail_on_high: bool):
    """Run a scan via the local backend API."""
    print(f"[*] Starting Sentinel DAST on {target_url}")
    print(f"[*] API Mode: {api_mode}")
    print(f"[*] Active Fuzzing: {fuzz_mode}")

    base_api = "http://127.0.0.1:8000/api/v1"
    
    # 1. Create scan
    payload = {
        "target_url": target_url,
        "is_api_scan": api_mode,
        "active_fuzzing": fuzz_mode,
        "use_browser": False,
        "max_depth": 3,
        "max_concurrency": 10
    }
    
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.post(f"{base_api}/scans", json=payload)
            resp.raise_for_status()
            scan_data = resp.json()
            scan_id = scan_data["scan_id"]
            print(f"[+] Scan started successfully. ID: {scan_id}")
        except Exception as e:
            print(f"[-] Failed to start scan: {e}")
            sys.exit(1)
            
        # 2. Poll for completion
        print("[*] Waiting for scan to complete...")
        while True:
            try:
                resp = await client.get(f"{base_api}/scans/{scan_id}")
                resp.raise_for_status()
                status_data = resp.json()
                
                status = status_data["status"]
                if status in ("completed", "failed", "cancelled"):
                    print(f"[*] Scan finished with status: {status}")
                    break
                    
                time.sleep(2)
            except Exception as e:
                print(f"[-] Error polling scan status: {e}")
                sys.exit(1)

        # 3. Analyze results
        findings = status_data.get("findings", [])
        severity_counts = status_data.get("severity_counts", {})
        
        print("\n=== SCAN RESULTS ===")
        print(f"Pages Visited: {status_data.get('pages_visited')}")
        print(f"Total Findings: {len(findings)}")
        print(f"Critical: {severity_counts.get('Critical', 0)}")
        print(f"High: {severity_counts.get('High', 0)}")
        print(f"Medium: {severity_counts.get('Medium', 0)}")
        print(f"Low: {severity_counts.get('Low', 0)}")
        
        if fail_on_high and (severity_counts.get("Critical", 0) > 0 or severity_counts.get("High", 0) > 0):
            print("\n[!] CRITICAL/HIGH VULNERABILITIES DETECTED!")
            print("[!] Failing CI/CD pipeline.")
            sys.exit(1)
            
        print("\n[+] Scan passed successfully.")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Sentinel DAST CLI for CI/CD")
    parser.add_argument("target", help="URL to scan (e.g. https://example.com or openapi.json URL)")
    parser.add_argument("--api", action="store_true", help="Parse the target as an OpenAPI/Swagger schema")
    parser.add_argument("--fuzz", action="store_true", help="Enable Active Fuzzing (WARNING: Offensive Mode)")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit with code 1 if High or Critical vulns are found")
    
    args = parser.parse_args()
    
    # Ensure URL is valid
    parsed = urlparse(args.target)
    if not parsed.scheme or not parsed.netloc:
        print("[-] Invalid target URL. Must include http:// or https://")
        sys.exit(1)
        
    asyncio.run(run_scan(args.target, args.api, args.fuzz, args.fail_on_high))


if __name__ == "__main__":
    main()
