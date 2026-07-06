import { Terminal, Key, Rocket, Server } from "lucide-react";

export function CiCdPanel() {
  const apiKey = "ci-cd-secret-key-change-me-in-prod"; // Mock key, would come from backend config

  const githubActionTemplate = `name: Sentinel DAST Scan

on:
  push:
    branches: [ "main" ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger Sentinel Scan
        run: |
          curl -X POST http://sentinel.your-company.internal:8000/api/v1/scans \\
            -H "Content-Type: application/json" \\
            -H "X-API-Key: \${{ secrets.SENTINEL_API_KEY }}" \\
            -d '{
              "target_url": "https://staging.your-app.com",
              "max_depth": 2,
              "max_concurrency": 10,
              "webhook_url": "\${{ secrets.SLACK_WEBHOOK_URL }}"
            }'
`;

  return (
    <div className="space-y-6">
      <div className="panel p-6">
        <div className="flex items-center gap-3 mb-4">
          <Rocket className="h-6 w-6 text-blue-500" />
          <h2 className="text-lg font-medium text-white">CI/CD Pipeline Integration</h2>
        </div>
        <p className="text-sm text-[#a3a3a3] mb-6">
          Integrate Sentinel DAST directly into your deployment pipelines. You can trigger automated security scans
          every time code is pushed to staging or production.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <h3 className="text-sm font-medium text-[#e5e5e5] flex items-center gap-2">
              <Key className="h-4 w-4 text-orange-500" />
              API Authentication
            </h3>
            <p className="text-xs text-[#737373]">
              To interact with the Sentinel API from an external runner, include the <code className="bg-[#262626] px-1 py-0.5 rounded text-white">X-API-Key</code> header.
            </p>
            <div className="bg-[#121212] border border-[#262626] p-3 rounded-lg flex items-center justify-between">
              <div>
                <div className="text-[10px] text-[#737373] uppercase mb-1">Master API Key</div>
                <div className="font-mono text-sm text-green-400">{apiKey}</div>
              </div>
              <button 
                onClick={() => navigator.clipboard.writeText(apiKey)}
                className="text-xs bg-[#262626] hover:bg-[#404040] text-white px-2 py-1 rounded transition-colors"
              >
                Copy
              </button>
            </div>
            <p className="text-[10px] text-yellow-500/80">
              Note: This key should be configured via the SENTINEL_API_KEY environment variable on your backend container.
            </p>
          </div>

          <div className="space-y-4">
            <h3 className="text-sm font-medium text-[#e5e5e5] flex items-center gap-2">
              <Server className="h-4 w-4 text-purple-500" />
              cURL Example
            </h3>
            <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg p-4 overflow-x-auto relative group">
              <pre className="text-xs font-mono text-[#a3a3a3] leading-relaxed">
<span className="text-blue-400">curl</span> -X POST http://localhost:8000/api/v1/scans \<br/>
  -H <span className="text-green-400">"Content-Type: application/json"</span> \<br/>
  -H <span className="text-green-400">"X-API-Key: {apiKey}"</span> \<br/>
  -d <span className="text-yellow-400">'{'{"target_url":"https://example.com"}'}'</span>
              </pre>
            </div>
          </div>
        </div>
      </div>

      <div className="panel p-6">
        <h3 className="text-sm font-medium text-white flex items-center gap-2 mb-4">
          <Terminal className="h-4 w-4 text-[#a3a3a3]" />
          GitHub Actions Template
        </h3>
        <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg p-4 overflow-x-auto">
          <pre className="text-xs font-mono text-[#e5e5e5] leading-relaxed whitespace-pre-wrap">
            {githubActionTemplate}
          </pre>
        </div>
      </div>
    </div>
  );
}
