export type ScanRequest = {
  target_url: string;
  max_depth?: number;
  max_concurrency?: number;
  page_timeout_ms?: number;
  same_domain_only?: boolean;
  use_browser?: boolean;
  stealth_mode?: boolean;
  active_fuzzing?: boolean;
  is_api_scan?: boolean;
  custom_headers?: Record<string, string>;
  auth_config?: {
    login_url: string;
    username_selector: string;
    password_selector: string;
    submit_selector: string;
    username: string;
    password: string;
  } | null;
};

export type Severity = "Critical" | "High" | "Medium" | "Low";

export type ScanStatus = "pending" | "running" | "completed" | "cancelled" | "failed";

export type ScanEventType =
  | "scan_started"
  | "page_visited"
  | "vulnerability_found"
  | "scan_progress"
  | "scan_finished"
  | "scan_cancelled"
  | "scan_failed"
  | "ping";

export type Finding = {
  url: string;
  vulnerability_type: string;
  severity: Severity;
  description: string;
  recommendation: string;
};

export type ScanEvent = {
  scan_id: string;
  event: ScanEventType;
  timestamp: string;
  data: Record<string, unknown>;
};

export type ScanCreateResponse = {
  scan_id: string;
  status: ScanStatus;
};

export type ScanSummary = {
  scan_id: string;
  status: ScanStatus;
  target_url: string;
  started_at: string | null;
  finished_at: string | null;
  pages_visited: number;
  findings_count: number;
  severity_counts: Record<Severity, number>;
  result: unknown | null;
  error: string | null;
};

export type DashboardState = {
  scanId: string | null;
  status: ScanStatus | "idle";
  targetUrl: string;
  pagesVisited: number;
  findingsCount: number;
  severityCounts: Record<Severity, number>;
  logs: string[];
  findings: Finding[];
  isRunning: boolean;
  isReconnecting: boolean;
};
