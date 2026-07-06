"use client";

import { useEffect, useRef } from "react";

type LogsPanelProps = {
  logs: string[];
};

export function LogsPanel({ logs }: LogsPanelProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  // Colorize log lines minimally for readability
  const formatLog = (log: string) => {
    if (log.includes("[SCAN]")) return <span className="text-info">{log}</span>;
    if (log.includes("[PAGE]")) return <span className="text-[#a3a3a3]">{log}</span>;
    if (log.includes("[STREAM]")) return <span className="text-[#737373]">{log}</span>;
    if (log.includes("[FINDING:CRITICAL]")) return <span className="text-critical font-bold">{log}</span>;
    if (log.includes("[FINDING:HIGH]")) return <span className="text-high font-semibold">{log}</span>;
    if (log.includes("[FINDING:MEDIUM]")) return <span className="text-medium">{log}</span>;
    if (log.includes("[FINDING:LOW]")) return <span className="text-low">{log}</span>;
    if (log.includes("Échoué") || log.includes("erreur")) return <span className="text-critical">{log}</span>;
    return log;
  };

  return (
    <div className="panel flex flex-col h-[250px]">
      <div className="panel-header">Execution Logs</div>
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto bg-[#0a0a0a] p-3 font-mono text-[11px] leading-snug text-[#d4d4d8]"
      >
        {logs.length === 0 ? (
          <div className="text-[#737373]">Awaiting execution...</div>
        ) : (
          <ul className="space-y-0.5">
            {logs.map((log, i) => (
              <li key={i}>{formatLog(log)}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
