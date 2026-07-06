"use client";

import React, { useState } from "react";
import { ChevronDown, ChevronRight, AlertTriangle } from "lucide-react";

import type { Finding, Severity } from "@/types/scan";

type FindingsTableProps = {
  findings: Finding[];
  severityCounts: Record<Severity, number>;
};

const severityColors: Record<Severity, string> = {
  Critical: "bg-critical",
  High: "bg-high",
  Medium: "bg-medium",
  Low: "bg-low",
};

export function FindingsTable({ findings, severityCounts }: FindingsTableProps) {
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<Severity | "All">("All");
  const [hiddenFindings, setHiddenFindings] = useState<Set<string>>(new Set());

  const handleFalsePositive = async (url: string, vulnerability_type: string) => {
    const key = `${url}|${vulnerability_type}`;
    setHiddenFindings(prev => new Set(prev).add(key));
    
    try {
      await fetch("/api/v1/false-positives", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, vulnerability_type })
      });
    } catch (err) {
      console.error("Failed to register false positive", err);
    }
  };

  const filteredFindings = findings.filter(
    (f) => {
      const key = `${f.url}|${f.vulnerability_type}`;
      if (hiddenFindings.has(key)) return false;
      return filterSeverity === "All" || f.severity === filterSeverity;
    }
  );

  return (
    <div className="panel mb-4 flex flex-col xl:flex-row divide-y xl:divide-y-0 xl:divide-x divide-border">
      {/* Sidebar Filter */}
      <div className="w-full xl:w-48 flex-shrink-0 bg-[#121212]">
        <div className="panel-header">Severity Filter</div>
        <div className="p-2 space-y-1">
          <button
            onClick={() => setFilterSeverity("All")}
            className={`w-full text-left px-3 py-1.5 text-sm rounded ${
              filterSeverity === "All" ? "bg-[#1a1a1a] font-semibold text-[#e5e5e5]" : "text-[#a3a3a3] hover:text-[#e5e5e5] hover:bg-[#1a1a1a]/50"
            }`}
          >
            All Findings
          </button>
          {(Object.keys(severityColors) as Severity[]).map((level) => (
            <button
              key={level}
              onClick={() => setFilterSeverity(level)}
              className={`w-full flex items-center justify-between px-3 py-1.5 text-sm rounded ${
                filterSeverity === level ? "bg-[#1a1a1a] font-semibold text-[#e5e5e5]" : "text-[#a3a3a3] hover:text-[#e5e5e5] hover:bg-[#1a1a1a]/50"
              }`}
            >
              <div className="flex items-center gap-2">
                <span className={`status-dot ${severityColors[level]}`}></span>
                <span>{level}</span>
              </div>
              <span className="font-mono text-xs">{severityCounts[level]}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Main Table */}
      <div className="flex-1 overflow-hidden flex flex-col">
        <div className="panel-header flex items-center justify-between">
          <span>Vulnerabilities</span>
          <span className="font-normal normal-case text-xs text-[#a3a3a3]">{filteredFindings.length} results</span>
        </div>
        
        <div className="overflow-auto max-h-[500px]">
          {filteredFindings.length === 0 ? (
            <div className="p-8 text-center text-sm text-[#737373]">
              No findings to display.
            </div>
          ) : (
            <table className="data-table w-full border-collapse">
              <thead className="sticky top-0 z-10">
                <tr>
                  <th className="w-8"></th>
                  <th className="w-24">Severity</th>
                  <th className="w-64">Vulnerability Type</th>
                  <th>Target Resource</th>
                </tr>
              </thead>
              <tbody className="text-[#e5e5e5]">
                {filteredFindings.map((finding, index) => {
                  const isExpanded = expandedIndex === index;
                  return (
                    <React.Fragment key={`${finding.url}-${finding.vulnerability_type}-${index}`}>
                      <tr 
                        className="cursor-pointer group hover:bg-[#1a1a1a]"
                        onClick={() => setExpandedIndex(isExpanded ? null : index)}
                      >
                        <td className="text-[#737373] group-hover:text-[#e5e5e5]">
                          {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        </td>
                        <td>
                          <div className="flex items-center gap-2">
                            <span className={`status-dot ${severityColors[finding.severity]}`}></span>
                            {finding.severity}
                          </div>
                        </td>
                        <td className="font-medium">{finding.vulnerability_type}</td>
                        <td className="font-mono text-xs text-[#a3a3a3] truncate max-w-md">
                          {finding.url}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-[#0f0f0f]">
                          <td colSpan={4} className="p-0 border-b border-[#262626]">
                            <div className="p-4 pl-12 space-y-4 border-l-2 border-blue-600 ml-[17px] my-2">
                              <div>
                                <div className="text-xs font-semibold text-[#737373] uppercase mb-1">Description</div>
                                <div className="text-sm text-[#d4d4d8] whitespace-pre-wrap">{finding.description}</div>
                              </div>
                              <div>
                                <div className="text-xs font-semibold text-[#737373] uppercase mb-1">Remediation</div>
                                <div className="text-sm text-[#d4d4d8] whitespace-pre-wrap">{finding.recommendation}</div>
                              </div>
                              <div className="pt-2">
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleFalsePositive(finding.url, finding.vulnerability_type);
                                  }}
                                  className="flex items-center gap-2 px-3 py-1.5 text-xs bg-[#1a1a1a] hover:bg-red-500/10 hover:text-red-500 text-[#a3a3a3] rounded border border-[#262626] transition-colors"
                                >
                                  <AlertTriangle size={14} />
                                  Mark as False Positive
                                </button>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
