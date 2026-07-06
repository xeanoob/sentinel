import { useEffect, useState } from "react";
import { Activity, ShieldAlert, Target, AlertTriangle } from "lucide-react";

type AnalyticsData = {
  total_scans: number;
  total_findings: number;
  severity_distribution: {
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
  };
  top_vulnerabilities: { name: string; count: number }[];
  recent_scans: { date: string | null; findings: number }[];
};

export function AnalyticsPanel() {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/v1/analytics")
      .then((res) => res.json())
      .then((json) => {
        setData(json);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to load analytics", err);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <div className="p-10 text-center text-[#737373]">Loading analytics...</div>;
  }

  if (!data) {
    return <div className="p-10 text-center text-red-500">Failed to load analytics data.</div>;
  }

  // Calculate percentages for the severity bar
  const total = data.total_findings || 1; // prevent div by 0
  const pCrit = (data.severity_distribution.Critical / total) * 100;
  const pHigh = (data.severity_distribution.High / total) * 100;
  const pMed = (data.severity_distribution.Medium / total) * 100;
  const pLow = (data.severity_distribution.Low / total) * 100;

  // Max findings for the trend chart
  const maxFindings = Math.max(...data.recent_scans.map(s => s.findings), 1);

  return (
    <div className="space-y-6">
      {/* Top KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="panel p-4 flex flex-col justify-center items-center">
          <Activity className="h-6 w-6 text-blue-500 mb-2" />
          <div className="text-3xl font-bold text-white">{data.total_scans}</div>
          <div className="text-xs text-[#a3a3a3] uppercase tracking-wide mt-1">Total Scans</div>
        </div>
        <div className="panel p-4 flex flex-col justify-center items-center">
          <ShieldAlert className="h-6 w-6 text-red-500 mb-2" />
          <div className="text-3xl font-bold text-red-500">{data.total_findings}</div>
          <div className="text-xs text-[#a3a3a3] uppercase tracking-wide mt-1">Total Vulnerabilities</div>
        </div>
        <div className="panel p-4 flex flex-col justify-center items-center">
          <AlertTriangle className="h-6 w-6 text-orange-500 mb-2" />
          <div className="text-3xl font-bold text-orange-500">{data.severity_distribution.High}</div>
          <div className="text-xs text-[#a3a3a3] uppercase tracking-wide mt-1">High Severity</div>
        </div>
        <div className="panel p-4 flex flex-col justify-center items-center">
          <Target className="h-6 w-6 text-green-500 mb-2" />
          <div className="text-3xl font-bold text-white">
            {data.total_scans > 0 ? (data.total_findings / data.total_scans).toFixed(1) : "0"}
          </div>
          <div className="text-xs text-[#a3a3a3] uppercase tracking-wide mt-1">Avg Findings / Scan</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="panel p-6">
          <h3 className="text-sm font-medium text-white mb-6">Severity Distribution</h3>
          
          <div className="h-4 w-full flex rounded-full overflow-hidden mb-6">
            <div style={{ width: `${pCrit}%` }} className="bg-red-600" title="Critical" />
            <div style={{ width: `${pHigh}%` }} className="bg-orange-500" title="High" />
            <div style={{ width: `${pMed}%` }} className="bg-yellow-500" title="Medium" />
            <div style={{ width: `${pLow}%` }} className="bg-blue-500" title="Low" />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="flex items-center justify-between p-3 border border-[#262626] rounded-lg bg-[#121212]">
              <span className="flex items-center gap-2 text-sm"><div className="w-3 h-3 rounded-full bg-red-600"/> Critical</span>
              <span className="font-mono text-white">{data.severity_distribution.Critical}</span>
            </div>
            <div className="flex items-center justify-between p-3 border border-[#262626] rounded-lg bg-[#121212]">
              <span className="flex items-center gap-2 text-sm"><div className="w-3 h-3 rounded-full bg-orange-500"/> High</span>
              <span className="font-mono text-white">{data.severity_distribution.High}</span>
            </div>
            <div className="flex items-center justify-between p-3 border border-[#262626] rounded-lg bg-[#121212]">
              <span className="flex items-center gap-2 text-sm"><div className="w-3 h-3 rounded-full bg-yellow-500"/> Medium</span>
              <span className="font-mono text-white">{data.severity_distribution.Medium}</span>
            </div>
            <div className="flex items-center justify-between p-3 border border-[#262626] rounded-lg bg-[#121212]">
              <span className="flex items-center gap-2 text-sm"><div className="w-3 h-3 rounded-full bg-blue-500"/> Low</span>
              <span className="font-mono text-white">{data.severity_distribution.Low}</span>
            </div>
          </div>
        </div>

        {/* Top Vulnerabilities */}
        <div className="panel p-6">
          <h3 className="text-sm font-medium text-white mb-6">Top Vulnerabilities</h3>
          {data.top_vulnerabilities.length === 0 ? (
            <div className="text-sm text-[#737373]">No vulnerabilities found yet.</div>
          ) : (
            <div className="space-y-4">
              {data.top_vulnerabilities.map((v, i) => (
                <div key={i} className="flex items-center justify-between">
                  <div className="flex items-center gap-3 w-full">
                    <span className="text-[#a3a3a3] font-mono text-xs w-4">{i + 1}.</span>
                    <span className="text-sm text-[#e5e5e5] truncate">{v.name}</span>
                  </div>
                  <span className="text-sm font-mono text-blue-400 bg-blue-400/10 px-2 py-0.5 rounded ml-4">
                    {v.count}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Trend Chart */}
      <div className="panel p-6">
        <h3 className="text-sm font-medium text-white mb-6">Findings Trend (Last 10 Scans)</h3>
        {data.recent_scans.length < 2 ? (
          <div className="text-sm text-[#737373]">Not enough scan history to display trend.</div>
        ) : (
          <div className="h-40 flex items-end gap-2 mt-10">
            {data.recent_scans.map((scan, i) => {
              const height = scan.findings > 0 ? (scan.findings / maxFindings) * 100 : 2; // minimum 2% for visibility
              const dateObj = scan.date ? new Date(scan.date) : null;
              const dateStr = dateObj ? `${dateObj.getMonth()+1}/${dateObj.getDate()}` : "N/A";
              return (
                <div key={i} className="flex-1 flex flex-col items-center group relative">
                  <div 
                    className="w-full bg-blue-600/80 hover:bg-blue-500 rounded-t transition-all"
                    style={{ height: `${height}%` }}
                  />
                  <div className="mt-2 text-[10px] text-[#737373] rotate-45 origin-left mb-4">{dateStr}</div>
                  
                  {/* Tooltip */}
                  <div className="absolute -top-8 bg-[#262626] text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none z-10">
                    {scan.findings} findings
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
