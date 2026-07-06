import { useState, useEffect } from "react";
import { ArrowLeft, CheckCircle, AlertTriangle, ShieldAlert } from "lucide-react";

type ComparePanelProps = {
  baseId: string;
  newId: string;
  onBack: () => void;
};

export function ComparePanel({ baseId, newId, onBack }: ComparePanelProps) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`http://localhost:8000/api/v1/scans/compare?base_id=${baseId}&new_id=${newId}`)
      .then((res) => res.json())
      .then((d) => {
        setData(d);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to compare", err);
        setLoading(false);
      });
  }, [baseId, newId]);

  if (loading) {
    return <div className="panel p-6 text-center text-[#737373]">Analyzing delta between scans...</div>;
  }

  if (!data) return <div className="panel p-6">Failed to load comparison.</div>;

  return (
    <div className="panel p-6">
      <button onClick={onBack} className="flex items-center gap-2 text-sm text-[#a3a3a3] hover:text-white mb-6">
        <ArrowLeft className="h-4 w-4" /> Back to History
      </button>

      <div className="grid grid-cols-3 gap-4 mb-8">
        <div className="bg-[#121212] p-4 rounded border border-[#262626] text-center">
          <CheckCircle className="h-6 w-6 text-green-500 mx-auto mb-2" />
          <div className="text-2xl font-bold text-white">{data.resolved_count}</div>
          <div className="text-sm text-[#a3a3a3]">Vulnerabilities Resolved</div>
        </div>
        <div className="bg-[#121212] p-4 rounded border border-[#262626] text-center">
          <AlertTriangle className="h-6 w-6 text-red-500 mx-auto mb-2" />
          <div className="text-2xl font-bold text-white">{data.introduced_count}</div>
          <div className="text-sm text-[#a3a3a3]">New Regressions</div>
        </div>
        <div className="bg-[#121212] p-4 rounded border border-[#262626] text-center">
          <ShieldAlert className="h-6 w-6 text-yellow-500 mx-auto mb-2" />
          <div className="text-2xl font-bold text-white">{data.persisted_count}</div>
          <div className="text-sm text-[#a3a3a3]">Persisting Vulnerabilities</div>
        </div>
      </div>

      <div className="space-y-6">
        {data.resolved.length > 0 && (
          <div>
            <h3 className="text-lg font-semibold text-green-500 mb-3 flex items-center gap-2">
              <CheckCircle className="h-5 w-5" /> Resolved Since Last Scan
            </h3>
            <ul className="space-y-2">
              {data.resolved.map((f: any, i: number) => (
                <li key={i} className="bg-[#121212] p-3 rounded border border-green-500/20">
                  <span className="font-bold">[{f.severity}]</span> {f.vulnerability_type} on {f.url}
                </li>
              ))}
            </ul>
          </div>
        )}

        {data.introduced.length > 0 && (
          <div>
            <h3 className="text-lg font-semibold text-red-500 mb-3 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" /> New Vulnerabilities Introduced
            </h3>
            <ul className="space-y-2">
              {data.introduced.map((f: any, i: number) => (
                <li key={i} className="bg-[#121212] p-3 rounded border border-red-500/20">
                  <span className="font-bold">[{f.severity}]</span> {f.vulnerability_type} on {f.url}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
