import type { ScanCreateResponse, ScanRequest, ScanSummary } from "@/types/scan";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_DAST_API_URL ?? "http://127.0.0.1:8000";

export function getApiBaseUrl(): string {
  return API_BASE_URL;
}

export function getScanStreamUrl(scanId: string): string {
  return `${API_BASE_URL}/api/v1/scans/${scanId}/stream`;
}

export async function createScan(request: ScanRequest): Promise<ScanCreateResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    throw new Error(`Failed to create scan (${response.status})`);
  }

  return response.json();
}

export async function getScan(scanId: string): Promise<ScanSummary> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans/${scanId}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch scan (${response.status})`);
  }
  return response.json();
}

export async function cancelScan(scanId: string): Promise<ScanSummary> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans/${scanId}/cancel`, {
    method: "POST",
  });
  if (!response.ok) {
    throw new Error(`Failed to cancel scan (${response.status})`);
  }
  return response.json();
}
