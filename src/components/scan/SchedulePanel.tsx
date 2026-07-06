import { useState, useEffect } from "react";
import { Calendar, Plus, Trash2, Clock } from "lucide-react";
import { DEFAULT_SCAN_OPTIONS } from "@/hooks/useScanStream";

type Schedule = {
  id: string;
  name: string;
  cron_expression: string;
  enabled: boolean;
  last_run: string | null;
  config: any;
};

export function SchedulePanel() {
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [newSchedule, setNewSchedule] = useState({
    name: "",
    cron_expression: "0 0 * * *", // Default: Daily at midnight
    target_url: "",
  });

  const fetchSchedules = () => {
    fetch("/api/v1/schedules")
      .then((res) => res.json())
      .then((data) => {
        setSchedules(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to load schedules", err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchSchedules();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSchedule.name || !newSchedule.target_url) return;

    try {
      await fetch("/api/v1/schedules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: newSchedule.name,
          cron_expression: newSchedule.cron_expression,
          config: {
            ...DEFAULT_SCAN_OPTIONS,
            target_url: newSchedule.target_url,
          },
        }),
      });
      setShowNew(false);
      setNewSchedule({ name: "", cron_expression: "0 0 * * *", target_url: "" });
      fetchSchedules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await fetch(`/api/v1/schedules/${id}`, { method: "DELETE" });
      fetchSchedules();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="panel p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-2">
          <Calendar className="h-5 w-5 text-blue-500" />
          <h2 className="text-lg font-semibold">Scheduled Scans</h2>
        </div>
        <button
          onClick={() => setShowNew(!showNew)}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded text-sm font-medium transition-colors"
        >
          <Plus className="h-4 w-4" />
          New Schedule
        </button>
      </div>

      {showNew && (
        <form onSubmit={handleCreate} className="mb-8 bg-[#121212] border border-[#262626] rounded-lg p-4">
          <h3 className="font-medium text-[#e5e5e5] mb-4">Create New Schedule</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label className="block text-xs text-[#a3a3a3] mb-1">Schedule Name</label>
              <input
                type="text"
                placeholder="Weekly Prod Scan"
                value={newSchedule.name}
                onChange={(e) => setNewSchedule({ ...newSchedule, name: e.target.value })}
                className="w-full rounded border border-[#262626] bg-[#0a0a0a] px-3 py-1.5 text-sm"
                required
              />
            </div>
            <div>
              <label className="block text-xs text-[#a3a3a3] mb-1">Target URL</label>
              <input
                type="url"
                placeholder="https://example.com"
                value={newSchedule.target_url}
                onChange={(e) => setNewSchedule({ ...newSchedule, target_url: e.target.value })}
                className="w-full rounded border border-[#262626] bg-[#0a0a0a] px-3 py-1.5 text-sm"
                required
              />
            </div>
            <div>
              <label className="block text-xs text-[#a3a3a3] mb-1">Cron Expression</label>
              <input
                type="text"
                placeholder="0 0 * * *"
                value={newSchedule.cron_expression}
                onChange={(e) => setNewSchedule({ ...newSchedule, cron_expression: e.target.value })}
                className="w-full rounded border border-[#262626] bg-[#0a0a0a] px-3 py-1.5 text-sm font-mono"
                required
              />
              <p className="text-[10px] text-[#737373] mt-1">Format: Min Hour Day Month Weekday</p>
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowNew(false)}
              className="px-3 py-1.5 text-sm text-[#a3a3a3] hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-3 py-1.5 bg-blue-600 text-white rounded text-sm font-medium hover:bg-blue-700"
            >
              Save Schedule
            </button>
          </div>
        </form>
      )}

      {loading ? (
        <div className="text-center py-10 text-[#737373]">Loading schedules...</div>
      ) : schedules.length === 0 ? (
        <div className="text-center py-10 text-[#737373]">No scheduled scans configured.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-[#1a1a1a] text-[#a3a3a3]">
              <tr>
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Target</th>
                <th className="px-4 py-2 font-medium">Schedule (Cron)</th>
                <th className="px-4 py-2 font-medium">Last Run</th>
                <th className="px-4 py-2 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#262626]">
              {schedules.map((schedule) => (
                <tr key={schedule.id} className="hover:bg-[#121212]">
                  <td className="px-4 py-3 font-medium text-[#e5e5e5]">{schedule.name}</td>
                  <td className="px-4 py-3 text-[#a3a3a3]">{schedule.config.target_url}</td>
                  <td className="px-4 py-3 font-mono text-xs text-blue-400 bg-blue-400/10 inline-block mt-2 rounded px-2 py-1">
                    {schedule.cron_expression}
                  </td>
                  <td className="px-4 py-3 text-[#a3a3a3]">
                    {schedule.last_run ? (
                      <div className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {new Date(schedule.last_run).toLocaleString()}
                      </div>
                    ) : (
                      "Never"
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleDelete(schedule.id)}
                      className="p-1.5 text-[#a3a3a3] hover:text-red-500 hover:bg-red-500/10 rounded transition-colors"
                      title="Delete Schedule"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
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
