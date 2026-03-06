// API client for the Bridge control plane

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

export interface Device {
  id: string;
  device_public_key: string;
  identity_public_key: string | null;
  platform: string;
  os_version: string;
  hardware_model: string;
  hostname: string;
  registered_at: string;
  last_seen: string;
  posture_score: number;
  access_tier: string;
  attestation_verified: boolean;
}

export interface HealthResponse {
  status: string;
  version: string;
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error("Health check failed");
  return res.json();
}

export async function fetchDevices(): Promise<Device[]> {
  const res = await fetch(`${API_BASE}/api/v1/devices`);
  if (!res.ok) throw new Error("Failed to fetch devices");
  return res.json();
}

export function tierColor(tier: string): string {
  switch (tier) {
    case "fullaccess":
      return "text-green-400";
    case "standard":
      return "text-blue-400";
    case "restricted":
      return "text-yellow-400";
    case "quarantined":
      return "text-red-400";
    default:
      return "text-gray-400";
  }
}

export function tierBadgeColor(tier: string): string {
  switch (tier) {
    case "fullaccess":
      return "bg-green-900/50 text-green-400 border-green-800";
    case "standard":
      return "bg-blue-900/50 text-blue-400 border-blue-800";
    case "restricted":
      return "bg-yellow-900/50 text-yellow-400 border-yellow-800";
    case "quarantined":
      return "bg-red-900/50 text-red-400 border-red-800";
    default:
      return "bg-gray-900/50 text-gray-400 border-gray-800";
  }
}

export function scoreColor(score: number): string {
  if (score >= 80) return "text-green-400";
  if (score >= 60) return "text-yellow-400";
  if (score >= 40) return "text-orange-400";
  return "text-red-400";
}

export function timeAgo(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);

  if (diffSecs < 60) return `${diffSecs}s ago`;
  const diffMins = Math.floor(diffSecs / 60);
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}
