import { useState, useEffect } from "react";
import { Clock, Download, ArrowRight } from "lucide-react";
import { ComparePanel } from "./ComparePanel";

type ScanHistoryItem = {
  scan_id: string;
  target_url: string;
  status: string;
  start_time: string;
  end_time: string;
  pages_visited: number;
  findings: any[];
};

export function HistoryPanel() {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [comparing, setComparing] = useState<[string, string] | null>(null);

  useEffect(() => {
    fetch("http://localhost:8000/api/v1/scans")
      .then((res) => res.json())
      .then((data) => {
        setHistory(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to load history", err);
        setLoading(false);
      });
  }, []);

  const handleCompare = (scanId: string) => {
    // If we click compare, we need another scan. For simplicity, just compare with the latest scan before it.
    const currentIndex = history.findIndex((h) => h.scan_id === scanId);
    if (currentIndex < history.length - 1) {
      setComparing([history[currentIndex + 1].scan_id, scanId]); // [Base, New]
    } else {
      alert("Need at least 2 scans to compare.");
    }
  };

  if (comparing) {
    return <ComparePanel baseId={comparing[0]} newId={comparing[1]} onBack={() => setComparing(null)} />;
  }

  return (
    <div className="panel p-6">
      <div className="flex items-center gap-2 mb-6">
        <Clock className="h-5 w-5 text-blue-500" />
        <h2 className="text-lg font-semibold">Scan History</h2>
      </div>

      {loading ? (
        <div className="text-center py-10 text-[#737373]">Loading history...</div>
      ) : history.length === 0 ? (
        <div className="text-center py-10 text-[#737373]">No scans found on disk.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-[#1a1a1a] text-[#a3a3a3]">
              <tr>
                <th className="px-4 py-2 font-medium">Date</th>
                <th className="px-4 py-2 font-medium">Target</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Pages</th>
                <th className="px-4 py-2 font-medium">Findings</th>
                <th className="px-4 py-2 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#262626]">
              {history.map((scan) => (
                <tr key={scan.scan_id} className="hover:bg-[#121212]">
                  <td className="px-4 py-3 whitespace-nowrap">
                    {scan.start_time ? new Date(scan.start_time).toLocaleString() : "Unknown"}
                  </td>
                  <td className="px-4 py-3 max-w-[200px] truncate">{scan.target_url}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                        scan.status === "completed"
                          ? "bg-green-500/10 text-green-500"
                          : scan.status === "failed"
                          ? "bg-red-500/10 text-red-500"
                          : "bg-blue-500/10 text-blue-500"
                      }`}
                    >
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">{scan.pages_visited}</td>
                  <td className="px-4 py-3">
                    <span className={`font-bold ${scan.findings.length > 0 ? "text-red-500" : "text-green-500"}`}>
                      {scan.findings.length}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex justify-end gap-2">
                      <button
                        onClick={() => handleCompare(scan.scan_id)}
                        className="p-1.5 text-[#a3a3a3] hover:text-blue-500 hover:bg-[#262626] rounded transition-colors"
                        title="Compare with previous"
                      >
                        <ArrowRight className="h-4 w-4" />
                      </button>
                      <a
                        href={`http://localhost:8000/api/v1/scans/${scan.scan_id}/pdf`}
                        target="_blank"
                        rel="noreferrer"
                        className="p-1.5 text-[#a3a3a3] hover:text-white hover:bg-[#262626] rounded transition-colors"
                        title="Export PDF"
                      >
                        <Download className="h-4 w-4" />
                      </a>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
