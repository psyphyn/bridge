"use client";

import { useEffect, useState } from "react";
import { fetchDevices, fetchHealth, scoreColor, tierBadgeColor, type Device, type HealthResponse } from "@/lib/api";

export default function OverviewPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchHealth().then(setHealth).catch(() => setError("Cannot reach API"));
    fetchDevices().then(setDevices).catch(() => {});
  }, []);

  const totalDevices = devices.length;
  const verifiedDevices = devices.filter((d) => d.attestation_verified).length;
  const avgScore = totalDevices > 0
    ? Math.round(devices.reduce((sum, d) => sum + d.posture_score, 0) / totalDevices)
    : 0;

  const tierCounts = devices.reduce(
    (acc, d) => {
      acc[d.access_tier] = (acc[d.access_tier] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Overview</h2>

      {error && (
        <div className="mb-6 rounded-lg border border-red-800 bg-red-900/30 p-4 text-red-400">
          {error}. Make sure the Bridge API is running on port 8080.
        </div>
      )}

      {/* Stats cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-8">
        <StatCard
          label="API Status"
          value={health ? "Online" : "Offline"}
          detail={health ? `v${health.version}` : ""}
          color={health ? "text-green-400" : "text-red-400"}
        />
        <StatCard
          label="Total Devices"
          value={totalDevices.toString()}
          detail={`${verifiedDevices} attested`}
        />
        <StatCard
          label="Avg Posture Score"
          value={totalDevices > 0 ? avgScore.toString() : "-"}
          color={totalDevices > 0 ? scoreColor(avgScore) : undefined}
        />
        <StatCard
          label="Platforms"
          value={new Set(devices.map((d) => d.platform)).size.toString()}
          detail={[...new Set(devices.map((d) => d.platform))].join(", ")}
        />
      </div>

      {/* Access tier distribution */}
      {totalDevices > 0 && (
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-6 mb-8">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Access Tier Distribution</h3>
          <div className="flex gap-3">
            {Object.entries(tierCounts).map(([tier, count]) => (
              <span
                key={tier}
                className={`rounded-full border px-3 py-1 text-xs font-medium ${tierBadgeColor(tier)}`}
              >
                {tier}: {count}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Empty state */}
      {totalDevices === 0 && !error && (
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-12 text-center">
          <p className="text-gray-500 mb-2">No devices registered yet.</p>
          <p className="text-sm text-gray-600">
            Start the Bridge daemon to register a device.
          </p>
        </div>
      )}
    </div>
  );
}

function StatCard({
  label,
  value,
  detail,
  color,
}: {
  label: string;
  value: string;
  detail?: string;
  color?: string;
}) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900 p-5">
      <p className="text-xs font-medium text-gray-500 uppercase tracking-wider">{label}</p>
      <p className={`mt-1 text-2xl font-bold ${color || "text-gray-100"}`}>{value}</p>
      {detail && <p className="mt-1 text-xs text-gray-500">{detail}</p>}
    </div>
  );
}
