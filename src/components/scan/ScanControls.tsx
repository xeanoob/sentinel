"use client";

import { useState } from "react";
import { Play, Square, Settings, ChevronDown, ChevronRight } from "lucide-react";

import { DEFAULT_SCAN_OPTIONS, type ScanOptions } from "@/hooks/useScanStream";

type ScanControlsProps = {
  targetUrl: string;
  isRunning: boolean;
  onTargetUrlChange: (url: string) => void;
  onStart: (url: string, options: ScanOptions) => void;
  onCancel: () => void;
};

export function ScanControls({
  targetUrl,
  isRunning,
  onTargetUrlChange,
  onStart,
  onCancel,
}: ScanControlsProps) {
  const [showOptions, setShowOptions] = useState(false);
  const [options, setOptions] = useState<ScanOptions>(DEFAULT_SCAN_OPTIONS);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (targetUrl && !isRunning) {
      onStart(targetUrl, options);
    }
  };

  return (
    <div className="panel mb-4">
      <div className="panel-header flex items-center justify-between">
        <span>Target Configuration</span>
        <span className="font-mono text-xs text-[#737373]">v1.0</span>
      </div>
      <div className="p-4">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex flex-col gap-3 sm:flex-row">
            <input
              type="url"
              placeholder="https://example.com"
              value={targetUrl}
              onChange={(e) => onTargetUrlChange(e.target.value)}
              disabled={isRunning}
              required
              className="flex-1 rounded border border-[#262626] bg-[#0a0a0a] px-3 py-1.5 text-sm text-[#e5e5e5] focus:border-blue-600 focus:outline-none disabled:opacity-50"
            />

            <button
              type="button"
              onClick={() => setShowOptions(!showOptions)}
              disabled={isRunning}
              className="flex items-center gap-2 rounded border border-[#262626] bg-[#121212] px-3 py-1.5 text-sm font-medium text-[#d4d4d8] hover:bg-[#1a1a1a] focus:outline-none disabled:opacity-50"
            >
              <Settings className="h-4 w-4" />
              Options
            </button>

            {isRunning ? (
              <button
                type="button"
                onClick={onCancel}
                className="flex items-center gap-2 rounded bg-red-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-red-700 focus:outline-none"
              >
                <Square className="h-4 w-4 fill-current" />
                Abort Scan
              </button>
            ) : (
              <button
                type="submit"
                disabled={!targetUrl}
                className="flex items-center gap-2 rounded bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700 focus:outline-none disabled:opacity-50"
              >
                <Play className="h-4 w-4 fill-current" />
                Run Scan
              </button>
            )}
          </div>

          {showOptions && !isRunning && (
            <div className="mt-4 rounded border border-[#262626] bg-[#0a0a0a] p-4 space-y-6">
              <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
                <div>
                  <label className="mb-1 block text-xs font-medium text-[#a3a3a3]">Max Depth</label>
                  <input
                    type="number"
                    min="1"
                    max="10"
                    value={options.maxDepth}
                    onChange={(e) => setOptions({ ...options, maxDepth: parseInt(e.target.value) || 1 })}
                    className="w-full rounded border border-[#262626] bg-[#121212] px-2 py-1 text-sm text-[#e5e5e5] focus:border-blue-600 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-[#a3a3a3]">Concurrency</label>
                  <input
                    type="number"
                    min="1"
                    max="50"
                    value={options.maxConcurrency}
                    onChange={(e) => setOptions({ ...options, maxConcurrency: parseInt(e.target.value) || 1 })}
                    className="w-full rounded border border-[#262626] bg-[#121212] px-2 py-1 text-sm text-[#e5e5e5] focus:border-blue-600 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-[#a3a3a3]">Timeout (ms)</label>
                  <input
                    type="number"
                    min="1000"
                    step="1000"
                    value={options.pageTimeoutMs}
                    onChange={(e) => setOptions({ ...options, pageTimeoutMs: parseInt(e.target.value) || 15000 })}
                    className="w-full rounded border border-[#262626] bg-[#121212] px-2 py-1 text-sm text-[#e5e5e5] focus:border-blue-600 focus:outline-none"
                  />
                </div>
                <div className="flex flex-col gap-2 pt-5">
                  <label className="flex items-center gap-2 text-sm text-[#d4d4d8]">
                    <input
                      type="checkbox"
                      checked={options.sameDomainOnly}
                      onChange={(e) => setOptions({ ...options, sameDomainOnly: e.target.checked })}
                      className="h-4 w-4 rounded border-[#262626] bg-[#121212] accent-blue-600"
                    />
                    Strict domain matching
                  </label>
                  <label className="flex items-center gap-2 text-sm text-[#d4d4d8]" title="Uses a Headless Browser (Playwright) to execute JavaScript. Slower but required for React/Next.js/Vercel.">
                    <input
                      type="checkbox"
                      checked={options.useBrowser}
                      onChange={(e) => setOptions({ ...options, useBrowser: e.target.checked })}
                      className="h-4 w-4 rounded border-[#262626] bg-[#121212] accent-blue-600"
                    />
                    SPA Mode (Execute JS)
                  </label>
                  <label className="flex items-center gap-2 text-sm text-[#d4d4d8]" title="Adds random delays between requests to evade WAFs and rate limiting.">
                    <input
                      type="checkbox"
                      checked={options.stealthMode}
                      onChange={(e) => setOptions({ ...options, stealthMode: e.target.checked })}
                      className="h-4 w-4 rounded border-[#262626] bg-[#121212] accent-blue-600"
                    />
                    Stealth Mode (Evasion)
                  </label>
                  <label className="flex items-center gap-2 text-sm text-[#ef4444]" title="DANGEROUS: Send mutated payloads to server to trigger errors. Use only with permission!">
                    <input
                      type="checkbox"
                      checked={options.activeFuzzing}
                      onChange={(e) => setOptions({ ...options, activeFuzzing: e.target.checked })}
                      className="h-4 w-4 rounded border-[#262626] bg-[#121212] accent-red-600"
                    />
                    🔥 Active Fuzzing
                  </label>
                  <label className="flex items-center gap-2 text-sm text-[#d4d4d8]" title="Parse target URL as an OpenAPI/Swagger schema">
                    <input
                      type="checkbox"
                      checked={options.isApiScan}
                      onChange={(e) => setOptions({ ...options, isApiScan: e.target.checked })}
                      className="h-4 w-4 rounded border-[#262626] bg-[#121212] accent-blue-600"
                    />
                    API/Swagger Mode
                  </label>
                </div>
              </div>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 border-t border-[#262626] pt-4">
                <div>
                  <label className="mb-2 block text-xs font-medium text-[#a3a3a3]">
                    Custom HTTP Headers (JSON format)
                  </label>
                  <textarea
                    placeholder='{"Authorization": "Bearer token", "x-vercel-protection-bypass": "secret"}'
                    className="w-full h-[120px] rounded border border-[#262626] bg-[#121212] px-3 py-2 text-sm font-mono text-[#e5e5e5] focus:border-blue-600 focus:outline-none resize-none"
                    value={Object.keys(options.customHeaders || {}).length > 0 ? JSON.stringify(options.customHeaders, null, 2) : ""}
                    onChange={(e) => {
                      try {
                        if (!e.target.value.trim()) {
                          setOptions({ ...options, customHeaders: {} });
                          return;
                        }
                        const parsed = JSON.parse(e.target.value);
                        if (typeof parsed === 'object' && parsed !== null) {
                          setOptions({ ...options, customHeaders: parsed });
                        }
                      } catch (err) {
                        // Allow typing invalid JSON temporarily
                      }
                    }}
                    onBlur={(e) => {
                      if (e.target.value.trim()) {
                         try {
                             const parsed = JSON.parse(e.target.value);
                             setOptions({ ...options, customHeaders: parsed });
                         } catch {
                             alert("Invalid JSON format for custom headers.");
                         }
                      }
                    }}
                  />
                </div>
                
                <div>
                  <label className="mb-2 block text-xs font-medium text-[#a3a3a3] flex items-center justify-between">
                    Auto-Login Configuration
                    <span className="text-[10px] text-blue-500 bg-blue-500/10 px-2 py-0.5 rounded">Requires SPA Mode</span>
                  </label>
                  <div className="grid grid-cols-2 gap-2">
                     <input
                        type="url"
                        placeholder="Login URL (e.g., /login)"
                        value={options.authConfig?.login_url ?? ""}
                        onChange={(e) => setOptions({ ...options, authConfig: { login_url: "", username: "", password: "", username_selector: "", password_selector: "", submit_selector: "", ...(options.authConfig || {}), login_url: e.target.value } as any })}
                        className="col-span-2 w-full rounded border border-[#262626] bg-[#121212] px-2 py-1 text-sm text-[#e5e5e5] focus:border-blue-600 focus:outline-none"
                     />
                     <input
                        type="text"
                        placeholder="Username (e.g., admin)"
                        value={options.authConfig?.username ?? ""}
                        onChange={(e) => setOptions({ ...options, authConfig: { login_url: "", username: "", password: "", username_selector: "", password_selector: "", submit_selector: "", ...(options.authConfig || {}), username: e.target.value } as any })}
                        className="w-full rounded border border-[#262626] bg-[#121212] px-2 py-1 text-sm text-[#e5e5e5] focus:border-blue-600 focus:outline-none"
                     />
                     <input
                        type="password"
                        placeholder="Password"
                        value={options.authConfig?.password ?? ""}
                        onChange={(e) => setOptions({ ...options, authConfig: { login_url: "", username: "", password: "", username_selector: "", password_selector: "", submit_selector: "", ...(options.authConfig || {}), password: e.target.value } as any })}
                        className="w-full rounded border border-[#262626] bg-[#121212] px-2 py-1 text-sm text-[#e5e5e5] focus:border-blue-600 focus:outline-none"
                     />
                     <input
                        type="text"
                        placeholder="Username CSS Selector"
                        value={options.authConfig?.username_selector ?? ""}
                        onChange={(e) => setOptions({ ...options, authConfig: { login_url: "", username: "", password: "", username_selector: "", password_selector: "", submit_selector: "", ...(options.authConfig || {}), username_selector: e.target.value } as any })}
                        className="w-full rounded border border-[#262626] bg-[#121212] px-2 py-1 text-sm font-mono text-[#e5e5e5] focus:border-blue-600 focus:outline-none"
                     />
                     <input
                        type="text"
                        placeholder="Password CSS Selector"
                        value={options.authConfig?.password_selector ?? ""}
                        onChange={(e) => setOptions({ ...options, authConfig: { login_url: "", username: "", password: "", username_selector: "", password_selector: "", submit_selector: "", ...(options.authConfig || {}), password_selector: e.target.value } as any })}
                        className="w-full rounded border border-[#262626] bg-[#121212] px-2 py-1 text-sm font-mono text-[#e5e5e5] focus:border-blue-600 focus:outline-none"
                     />
                     <input
                        type="text"
                        placeholder="Submit Button Selector"
                        value={options.authConfig?.submit_selector ?? ""}
                        onChange={(e) => setOptions({ ...options, authConfig: { login_url: "", username: "", password: "", username_selector: "", password_selector: "", submit_selector: "", ...(options.authConfig || {}), submit_selector: e.target.value } as any })}
                        className="col-span-2 w-full rounded border border-[#262626] bg-[#121212] px-2 py-1 text-sm font-mono text-[#e5e5e5] focus:border-blue-600 focus:outline-none"
                     />
                  </div>
                </div>
                
                <div className="col-span-1 lg:col-span-2 mt-4 pt-4 border-t border-[#262626]">
                  <label className="mb-2 block text-xs font-medium text-[#a3a3a3] flex items-center justify-between">
                    Webhook Alerts
                    <span className="text-[10px] text-blue-500 bg-blue-500/10 px-2 py-0.5 rounded">Slack / Discord</span>
                  </label>
                  <input
                    type="url"
                    placeholder="https://hooks.slack.com/services/..."
                    value={options.webhookUrl}
                    onChange={(e) => setOptions({ ...options, webhookUrl: e.target.value })}
                    className="w-full rounded border border-[#262626] bg-[#121212] px-3 py-2 text-sm text-[#e5e5e5] focus:border-blue-600 focus:outline-none"
                  />
                  <p className="mt-1 text-xs text-[#737373]">
                    Receive an automatic notification if High or Critical vulnerabilities are found.
                  </p>
                </div>
              </div>
            </div>
          )}
        </form>
      </div>
    </div>
  );
}
