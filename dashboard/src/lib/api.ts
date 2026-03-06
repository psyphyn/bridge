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

// ── Policy types ─────────────────────────────────────────────────────

export type Action =
  | { Allow: Record<string, never> } | "Allow"
  | { Block: { reason: string } }
  | { ShadowCopy: Record<string, never> } | "ShadowCopy"
  | { Alert: { severity: string; message: string } }
  | { Redirect: { url: string } };

export type Condition =
  | { DomainMatches: string[] }
  | { PortIs: number }
  | { InGroup: string }
  | { NotInGroup: string }
  | { ApplicationIs: string }
  | { AccessTierBelow: string }
  | { AccessTierAtLeast: string }
  | { PlatformIs: string }
  | { ProtocolIs: string }
  | { DestIpInRange: string };

export interface PolicyRule {
  name: string;
  conditions: Condition[];
  action: Action;
}

export interface PolicySet {
  name: string;
  default_action: Action;
  rules: PolicyRule[];
}

export async function fetchPolicies(): Promise<PolicySet[]> {
  const res = await fetch(`${API_BASE}/api/v1/policies`);
  if (!res.ok) throw new Error("Failed to fetch policies");
  return res.json();
}

export async function fetchPolicy(name: string): Promise<PolicySet> {
  const res = await fetch(`${API_BASE}/api/v1/policies/${encodeURIComponent(name)}`);
  if (!res.ok) throw new Error("Policy not found");
  return res.json();
}

export async function upsertPolicy(policy: { name: string; default_action?: Action; rules: PolicyRule[] }): Promise<PolicySet> {
  const res = await fetch(`${API_BASE}/api/v1/policies`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(policy),
  });
  if (!res.ok) throw new Error("Failed to save policy");
  return res.json();
}

export async function deletePolicy(name: string): Promise<void> {
  const res = await fetch(`${API_BASE}/api/v1/policies/${encodeURIComponent(name)}`, {
    method: "DELETE",
  });
  if (!res.ok && res.status !== 204) throw new Error("Failed to delete policy");
}

// ── Security events (SIEM) ───────────────────────────────────────────

export interface SecurityEvent {
  id: string;
  timestamp: string;
  category: string;
  severity: string;
  outcome: string;
  message: string;
  device_id: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  domain: string | null;
  application: string | null;
  dst_port: number | null;
  protocol: string | null;
  bytes_out: number | null;
  bytes_in: number | null;
  detector: string;
  metadata: Record<string, string>;
}

export interface EventListResponse {
  events: SecurityEvent[];
  total: number;
}

export interface EventStats {
  total: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
}

export async function fetchEvents(params?: {
  category?: string;
  min_severity?: string;
  limit?: number;
}): Promise<EventListResponse> {
  const query = new URLSearchParams();
  if (params?.category) query.set("category", params.category);
  if (params?.min_severity) query.set("min_severity", params.min_severity);
  if (params?.limit) query.set("limit", String(params.limit));
  const qs = query.toString();
  const res = await fetch(`${API_BASE}/api/v1/events${qs ? `?${qs}` : ""}`);
  if (!res.ok) throw new Error("Failed to fetch events");
  return res.json();
}

export async function fetchEventStats(): Promise<EventStats> {
  const res = await fetch(`${API_BASE}/api/v1/events/stats`);
  if (!res.ok) throw new Error("Failed to fetch event stats");
  return res.json();
}

export function severityColor(severity: string): string {
  switch (severity) {
    case "Critical": return "text-red-400 bg-red-900/50 border-red-800";
    case "High": return "text-orange-400 bg-orange-900/50 border-orange-800";
    case "Medium": return "text-yellow-400 bg-yellow-900/50 border-yellow-800";
    case "Low": return "text-blue-400 bg-blue-900/50 border-blue-800";
    default: return "text-gray-400 bg-gray-900/50 border-gray-800";
  }
}

export function categoryIcon(category: string): string {
  switch (category) {
    case "DataLoss": return "🔓";
    case "CommandAndControl": return "🎯";
    case "DnsThreat": return "🌐";
    case "Exfiltration": return "📤";
    case "PolicyViolation": return "⛔";
    case "TunnelEvent": return "🔗";
    case "PostureChange": return "🛡️";
    default: return "📋";
  }
}

// ── Helpers ──────────────────────────────────────────────────────────

export function actionLabel(action: Action): string {
  if (action === "Allow") return "Allow";
  if (action === "ShadowCopy") return "Shadow Copy";
  if (typeof action === "object") {
    if ("Allow" in action) return "Allow";
    if ("Block" in action) return `Block: ${action.Block.reason}`;
    if ("ShadowCopy" in action) return "Shadow Copy";
    if ("Alert" in action) return `Alert: ${action.Alert.message}`;
    if ("Redirect" in action) return `Redirect: ${action.Redirect.url}`;
  }
  return "Unknown";
}

export function actionBadgeColor(action: Action): string {
  if (action === "Allow" || (typeof action === "object" && "Allow" in action))
    return "bg-green-900/50 text-green-400 border-green-800";
  if (typeof action === "object" && "Block" in action)
    return "bg-red-900/50 text-red-400 border-red-800";
  if (action === "ShadowCopy" || (typeof action === "object" && "ShadowCopy" in action))
    return "bg-purple-900/50 text-purple-400 border-purple-800";
  if (typeof action === "object" && "Alert" in action)
    return "bg-yellow-900/50 text-yellow-400 border-yellow-800";
  return "bg-gray-900/50 text-gray-400 border-gray-800";
}

export function conditionLabel(condition: Condition): string {
  if ("DomainMatches" in condition) return `Domain: ${condition.DomainMatches.join(", ")}`;
  if ("PortIs" in condition) return `Port: ${condition.PortIs}`;
  if ("InGroup" in condition) return `In group: ${condition.InGroup}`;
  if ("NotInGroup" in condition) return `Not in group: ${condition.NotInGroup}`;
  if ("ApplicationIs" in condition) return `App: ${condition.ApplicationIs}`;
  if ("AccessTierBelow" in condition) return `Tier below: ${condition.AccessTierBelow}`;
  if ("AccessTierAtLeast" in condition) return `Tier ≥ ${condition.AccessTierAtLeast}`;
  if ("PlatformIs" in condition) return `Platform: ${condition.PlatformIs}`;
  if ("ProtocolIs" in condition) return `Protocol: ${condition.ProtocolIs}`;
  if ("DestIpInRange" in condition) return `IP range: ${condition.DestIpInRange}`;
  return "Unknown condition";
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
