"use client";

import { useState } from "react";
import { Shield } from "lucide-react";

import { FindingsTable } from "@/components/scan/FindingsTable";
import { KpiPanel } from "@/components/scan/KpiPanel";
import { LogsPanel } from "@/components/scan/LogsPanel";
import { ScanControls } from "@/components/scan/ScanControls";
import { useScanStream } from "@/hooks/useScanStream";

import { HistoryPanel } from "@/components/scan/HistoryPanel";
import { SchedulePanel } from "@/components/scan/SchedulePanel";
import { AnalyticsPanel } from "@/components/scan/AnalyticsPanel";
import { CiCdPanel } from "@/components/scan/CiCdPanel";

export function Dashboard() {
  const { state, startScan, cancelScan } = useScanStream();
  const [targetUrl, setTargetUrl] = useState("https://example.com/");
  const [activeTab, setActiveTab] = useState<"analytics" | "live" | "history" | "schedules" | "cicd">("analytics");

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-[#e5e5e5]">

      {/* Main Content Area */}
      <main className="mx-auto max-w-[1600px] p-6">
        
        {/* Minimal Header */}
        <div className="mb-6 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-medium text-white">Sentinel Scanner</h1>
          </div>
          
          {(state.status === "completed" || state.status === "failed" || state.status === "cancelled") && state.scanId && (
            <a 
              href={`http://localhost:8000/api/v1/scans/${state.scanId}/pdf`}
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 text-sm bg-[#121212] border border-[#262626] rounded text-[#a3a3a3] hover:text-white hover:border-[#404040] transition-colors"
            >
              Export PDF
            </a>
          )}
        </div>

        {/* Tabs */}
        <div className="mb-6 flex space-x-1 border-b border-[#262626]">
          <button
            onClick={() => setActiveTab("analytics")}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === "analytics"
                ? "border-blue-600 text-blue-500"
                : "border-transparent text-[#a3a3a3] hover:text-[#e5e5e5]"
            }`}
          >
            Dashboard
          </button>
          <button
            onClick={() => setActiveTab("live")}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === "live"
                ? "border-blue-600 text-blue-500"
                : "border-transparent text-[#a3a3a3] hover:text-[#e5e5e5]"
            }`}
          >
            Live Scan
          </button>
          <button
            onClick={() => setActiveTab("history")}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === "history"
                ? "border-blue-600 text-blue-500"
                : "border-transparent text-[#a3a3a3] hover:text-[#e5e5e5]"
            }`}
          >
            History & Compare
          </button>
          <button
            onClick={() => setActiveTab("schedules")}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === "schedules"
                ? "border-blue-600 text-blue-500"
                : "border-transparent text-[#a3a3a3] hover:text-[#e5e5e5]"
            }`}
          >
            Scheduled Scans
          </button>
          <button
            onClick={() => setActiveTab("cicd")}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === "cicd"
                ? "border-blue-600 text-blue-500"
                : "border-transparent text-[#a3a3a3] hover:text-[#e5e5e5]"
            }`}
          >
            CI/CD Pipeline
          </button>
        </div>

        {activeTab === "analytics" && <AnalyticsPanel />}
        {activeTab === "cicd" && <CiCdPanel />}
        {activeTab === "live" && (
          <>
            <ScanControls
              targetUrl={targetUrl}
              isRunning={state.isRunning}
              onTargetUrlChange={setTargetUrl}
              onStart={startScan}
              onCancel={cancelScan}
            />

            {/* Flat Progress Bar */}
            {state.isRunning && (
              <div className="mb-4 flex items-center gap-3">
                <div className="text-xs font-mono text-[#a3a3a3] uppercase w-32">Scan Progress</div>
                <div className="flex-1 h-1.5 bg-[#121212] rounded-none overflow-hidden border border-[#262626]">
                  <div
                    className="h-full bg-blue-600 transition-all duration-200"
                    style={{ width: state.pagesVisited > 0 ? `${Math.min(95, state.pagesVisited * 5)}%` : "5%" }}
                  />
                </div>
              </div>
            )}

            <KpiPanel
              status={state.status}
              pagesVisited={state.pagesVisited}
              findingsCount={state.findingsCount}
              severityCounts={state.severityCounts}
              isReconnecting={state.isReconnecting}
            />

            {/* Empty State / Table Container */}
            {state.status === "idle" && !state.isRunning ? (
              <div className="panel mb-4 flex h-[300px] flex-col items-center justify-center border-dashed border-[#262626] text-center">
                <Shield className="mb-3 h-8 w-8 text-[#404040]" />
                <div className="text-sm font-medium text-[#d4d4d8]">No active scan</div>
                <div className="text-xs text-[#737373] mt-1">Configure target and initiate scan to view results.</div>
              </div>
            ) : (
              <FindingsTable findings={state.findings} severityCounts={state.severityCounts} />
            )}

            <LogsPanel logs={state.logs} />
          </>
        )}
        {activeTab === "history" && <HistoryPanel />}
        {activeTab === "schedules" && <SchedulePanel />}
      </main>
    </div>
  );
}
