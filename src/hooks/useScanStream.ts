"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import {
  cancelScan as cancelScanRequest,
  createScan,
  getScan,
  getScanStreamUrl,
} from "@/lib/api";
import type {
  DashboardState,
  Finding,
  ScanEvent,
  ScanStatus,
  Severity,
} from "@/types/scan";

export type ScanOptions = {
  maxDepth: number;
  maxConcurrency: number;
  pageTimeoutMs: number;
  sameDomainOnly: boolean;
  useBrowser: boolean;
  stealthMode: boolean;
  activeFuzzing: boolean;
  isApiScan: boolean;
  webhookUrl: string;
  customHeaders: Record<string, string>;
  authConfig?: {
    login_url: string;
    username_selector: string;
    password_selector: string;
    submit_selector: string;
    username: string;
    password: string;
  } | null;
};

export const DEFAULT_SCAN_OPTIONS: ScanOptions = {
  maxDepth: 2,
  maxConcurrency: 5,
  pageTimeoutMs: 5000,
  sameDomainOnly: true,
  useBrowser: false,
  stealthMode: false,
  activeFuzzing: false,
  isApiScan: false,
  webhookUrl: "",
  customHeaders: {},
  authConfig: null,
};

const EMPTY_SEVERITY: Record<Severity, number> = {
  Critical: 0,
  High: 0,
  Medium: 0,
  Low: 0,
};

const INITIAL_STATE: DashboardState = {
  scanId: null,
  status: "idle",
  targetUrl: "",
  pagesVisited: 0,
  findingsCount: 0,
  severityCounts: { ...EMPTY_SEVERITY },
  logs: [],
  findings: [],
  isRunning: false,
  isReconnecting: false,
};

const SCAN_ID_STORAGE_KEY = "dast_active_scan_id";

function pushLog(prev: string[], line: string): string[] {
  const next = [...prev, line];
  return next.length > 400 ? next.slice(next.length - 400) : next;
}

function parseEvent(raw: MessageEvent): ScanEvent {
  return JSON.parse(raw.data) as ScanEvent;
}

export function useScanStream() {
  const [state, setState] = useState<DashboardState>(INITIAL_STATE);
  const esRef = useRef<EventSource | null>(null);
  const scanIdRef = useRef<string | null>(null);
  const terminalRef = useRef(false);
  const seenFindingsRef = useRef<Set<string>>(new Set());

  const closeStream = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
  }, []);

  const appendFinding = useCallback((finding: Finding) => {
    const key = `${finding.url}|${finding.vulnerability_type}|${finding.description}`;
    if (seenFindingsRef.current.has(key)) {
      return;
    }
    seenFindingsRef.current.add(key);

    setState((prev) => ({
      ...prev,
      findings: [finding, ...prev.findings],
      findingsCount: prev.findingsCount + 1,
      severityCounts: {
        ...prev.severityCounts,
        [finding.severity]: prev.severityCounts[finding.severity] + 1,
      },
    }));
  }, []);

  const connectStream = useCallback(
    (scanId: string, reconnecting = false) => {
      closeStream();
      terminalRef.current = false;
      seenFindingsRef.current.clear();
      scanIdRef.current = scanId;

      setState((prev) => ({
        ...prev,
        scanId,
        isRunning: true,
        isReconnecting: reconnecting,
        logs: reconnecting ? [] : prev.logs,
        findings: reconnecting ? [] : prev.findings,
        severityCounts: reconnecting ? { ...EMPTY_SEVERITY } : prev.severityCounts,
        findingsCount: reconnecting ? 0 : prev.findingsCount,
      }));

      const es = new EventSource(getScanStreamUrl(scanId));
      esRef.current = es;

      const handleTerminal = (status: ScanStatus, logLine: string) => {
        if (terminalRef.current) return;
        terminalRef.current = true;
        setState((prev) => ({
          ...prev,
          status,
          isRunning: false,
          isReconnecting: false,
          logs: pushLog(prev.logs, logLine),
        }));
        closeStream();
        localStorage.removeItem(SCAN_ID_STORAGE_KEY);
      };

      es.addEventListener("open", () => {
        setState((prev) => ({
          ...prev,
          isReconnecting: false,
          logs: pushLog(prev.logs, `[STREAM] Connexion établie — scan_id=${scanId}`),
        }));
      });

      es.addEventListener("scan_started", (evt) => {
        const payload = parseEvent(evt as MessageEvent);
        const data = payload.data;
        setState((prev) => ({
          ...prev,
          status: "running",
          targetUrl: String(data.target_url ?? prev.targetUrl),
          logs: pushLog(
            prev.logs,
            `[SCAN] Démarré — cible=${String(data.target_url)} profondeur=${String(data.max_depth)}`,
          ),
        }));
      });

      es.addEventListener("page_visited", (evt) => {
        const payload = parseEvent(evt as MessageEvent);
        const data = payload.data;
        const pagesVisited = Number(data.pages_visited ?? 0);
        const statusCode = data.error ? "ERR" : String(data.status_code ?? "NA");
        setState((prev) => ({
          ...prev,
          pagesVisited,
          logs: pushLog(
            prev.logs,
            `[PAGE] ${statusCode} ${String(data.url)}${data.error ? ` — ${String(data.error)}` : ""}`,
          ),
        }));
      });

      es.addEventListener("vulnerability_found", (evt) => {
        const payload = parseEvent(evt as MessageEvent);
        const finding = payload.data.finding as Finding;
        appendFinding(finding);
        setState((prev) => ({
          ...prev,
          logs: pushLog(
            prev.logs,
            `[FINDING:${finding.severity.toUpperCase()}] ${finding.vulnerability_type} — ${finding.url}`,
          ),
        }));
      });

      es.addEventListener("scan_progress", (evt) => {
        const payload = parseEvent(evt as MessageEvent);
        const data = payload.data;
        setState((prev) => ({
          ...prev,
          pagesVisited: Number(data.pages_visited ?? prev.pagesVisited),
          findingsCount: Number(data.findings_count ?? prev.findingsCount),
        }));
      });

      es.addEventListener("scan_finished", (evt) => {
        const payload = parseEvent(evt as MessageEvent);
        const data = payload.data;
        setState((prev) => ({
          ...prev,
          pagesVisited: Number(data.pages_visited ?? prev.pagesVisited),
          findingsCount: Number(data.findings_count ?? prev.findingsCount),
        }));
        handleTerminal("completed", `[SCAN] Terminé — ${String(data.pages_visited)} pages analysées`);
      });

      es.addEventListener("scan_cancelled", (evt) => {
        const payload = parseEvent(evt as MessageEvent);
        handleTerminal("cancelled", `[SCAN] Annulé — ${String(payload.data.pages_visited)} pages`);
      });

      es.addEventListener("scan_failed", (evt) => {
        const payload = parseEvent(evt as MessageEvent);
        handleTerminal("failed", `[SCAN] Échoué — ${String(payload.data.error ?? "erreur inconnue")}`);
      });

      es.onerror = () => {
        if (terminalRef.current) {
          closeStream();
          return;
        }
        setState((prev) => {
          if (prev.status === "running") {
            return {
              ...prev,
              isReconnecting: true,
              logs: pushLog(prev.logs, "[STREAM] Déconnecté, reconnexion en cours..."),
            };
          }
          return prev;
        });
      };
    },
    [appendFinding, closeStream],
  );

  const startScan = useCallback(
    async (targetUrl: string, options?: Partial<ScanOptions>) => {
      closeStream();
      terminalRef.current = false;
      seenFindingsRef.current.clear();
      localStorage.removeItem(SCAN_ID_STORAGE_KEY);

      const opts = { ...DEFAULT_SCAN_OPTIONS, ...options };

      // Ensure authConfig is only sent if fully populated (basic validation)
      let auth_config = undefined;
      if (opts.authConfig && opts.authConfig.login_url && opts.authConfig.username_selector) {
        auth_config = opts.authConfig;
      }

      setState({
        ...INITIAL_STATE,
        targetUrl,
        status: "pending",
        isRunning: true,
        logs: [`[SCAN] Création du scan pour ${targetUrl}...`],
      });

      const created = await createScan({
        target_url: targetUrl,
        max_depth: opts.maxDepth,
        max_concurrency: opts.maxConcurrency,
        page_timeout_ms: opts.pageTimeoutMs,
        same_domain_only: opts.sameDomainOnly,
        use_browser: opts.useBrowser,
        stealth_mode: opts.stealthMode,
        active_fuzzing: opts.activeFuzzing,
        is_api_scan: opts.isApiScan,
        webhook_url: opts.webhookUrl || undefined,
        custom_headers: opts.customHeaders,
        auth_config: auth_config,
      });

      localStorage.setItem(SCAN_ID_STORAGE_KEY, created.scan_id);
      connectStream(created.scan_id);
    },
    [closeStream, connectStream],
  );

  const cancelScan = useCallback(async () => {
    const scanId = scanIdRef.current;
    if (!scanId) return;

    setState((prev) => ({
      ...prev,
      logs: pushLog(prev.logs, "[SCAN] Annulation demandée..."),
    }));

    closeStream();
    terminalRef.current = true;

    try {
      const summary = await cancelScanRequest(scanId);
      setState((prev) => ({
        ...prev,
        status: summary.status,
        pagesVisited: summary.pages_visited,
        findingsCount: summary.findings_count,
        severityCounts: summary.severity_counts,
        isRunning: false,
        isReconnecting: false,
        logs: pushLog(prev.logs, `[SCAN] Annulé — ${summary.pages_visited} pages`),
      }));
    } catch (err) {
      // If backend says 404 (e.g. server restarted), just force reset the UI
      setState(INITIAL_STATE);
    } finally {
      localStorage.removeItem(SCAN_ID_STORAGE_KEY);
    }
  }, [closeStream]);

  const resetScan = useCallback(() => {
    closeStream();
    terminalRef.current = false;
    seenFindingsRef.current.clear();
    localStorage.removeItem(SCAN_ID_STORAGE_KEY);
    setState(INITIAL_STATE);
  }, [closeStream]);

  useEffect(() => {
    const storedScanId = localStorage.getItem(SCAN_ID_STORAGE_KEY);
    if (!storedScanId) return;

    void (async () => {
      try {
        const summary = await getScan(storedScanId);
        setState((prev) => ({
          ...prev,
          scanId: summary.scan_id,
          status: summary.status,
          targetUrl: summary.target_url,
          pagesVisited: summary.pages_visited,
          findingsCount: summary.findings_count,
          severityCounts: summary.severity_counts,
          isRunning: summary.status === "running" || summary.status === "pending",
        }));

        if (summary.status === "running" || summary.status === "pending") {
          connectStream(storedScanId, true);
        }
      } catch {
        localStorage.removeItem(SCAN_ID_STORAGE_KEY);
      }
    })();

    return () => {
      closeStream();
    };
  }, [closeStream, connectStream]);

  return {
    state,
    startScan,
    cancelScan,
    resetScan,
  };
}
