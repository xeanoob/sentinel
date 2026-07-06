"use client";

import type { ScanStatus, Severity } from "@/types/scan";

type KpiPanelProps = {
  status: ScanStatus;
  pagesVisited: number;
  findingsCount: number;
  severityCounts: Record<Severity, number>;
  isReconnecting: boolean;
};

export function KpiPanel({
  status,
  pagesVisited,
  findingsCount,
  severityCounts,
  isReconnecting,
}: KpiPanelProps) {
  
  const getStatusDisplay = () => {
    if (isReconnecting) return { text: "Reconnecting", color: "bg-medium" };
    switch (status) {
      case "idle": return { text: "Idle", color: "bg-[#737373]" };
      case "pending": return { text: "Pending", color: "bg-info" };
      case "running": return { text: "Running", color: "bg-accent" };
      case "completed": return { text: "Completed", color: "bg-low" };
      case "cancelled": return { text: "Cancelled", color: "bg-medium" };
      case "failed": return { text: "Failed", color: "bg-critical" };
      default: return { text: "Unknown", color: "bg-[#737373]" };
    }
  };

  const stat = getStatusDisplay();

  return (
    <div className="panel mb-4 grid grid-cols-1 divide-y divide-[#262626] sm:grid-cols-4 sm:divide-y-0 sm:divide-x">
      <div className="p-4">
        <div className="text-xs font-medium text-[#a3a3a3] uppercase mb-1">Status</div>
        <div className="flex items-center gap-2">
          <span className={`status-dot ${stat.color}`}></span>
          <span className="text-lg font-semibold text-[#e5e5e5]">{stat.text}</span>
        </div>
      </div>
      <div className="p-4">
        <div className="text-xs font-medium text-[#a3a3a3] uppercase mb-1">Pages Crawled</div>
        <div className="text-lg font-mono text-[#e5e5e5]">{pagesVisited}</div>
      </div>
      <div className="p-4">
        <div className="text-xs font-medium text-[#a3a3a3] uppercase mb-1">Total Findings</div>
        <div className="text-lg font-mono text-[#e5e5e5]">{findingsCount}</div>
      </div>
      <div className="p-4 flex flex-col justify-center">
        <div className="flex items-center gap-3 text-xs font-mono text-[#e5e5e5]">
          <div className="flex items-center gap-1.5"><span className="status-dot bg-critical"></span>C:{severityCounts.Critical}</div>
          <div className="flex items-center gap-1.5"><span className="status-dot bg-high"></span>H:{severityCounts.High}</div>
          <div className="flex items-center gap-1.5"><span className="status-dot bg-medium"></span>M:{severityCounts.Medium}</div>
          <div className="flex items-center gap-1.5"><span className="status-dot bg-low"></span>L:{severityCounts.Low}</div>
        </div>
      </div>
    </div>
  );
}
