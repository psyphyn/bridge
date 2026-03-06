"use client";

import { useEffect, useState } from "react";
import {
  fetchDevices,
  scoreColor,
  tierBadgeColor,
  timeAgo,
  type Device,
} from "@/lib/api";

export default function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDevices()
      .then(setDevices)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Devices</h2>
        <span className="text-sm text-gray-500">{devices.length} registered</span>
      </div>

      {loading ? (
        <p className="text-gray-500">Loading...</p>
      ) : devices.length === 0 ? (
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-12 text-center">
          <p className="text-gray-500">No devices registered yet.</p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead className="bg-gray-900 text-xs uppercase text-gray-500">
              <tr>
                <th className="px-4 py-3 text-left">Device</th>
                <th className="px-4 py-3 text-left">Platform</th>
                <th className="px-4 py-3 text-left">Posture</th>
                <th className="px-4 py-3 text-left">Access Tier</th>
                <th className="px-4 py-3 text-left">Attested</th>
                <th className="px-4 py-3 text-left">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {devices.map((device) => (
                <DeviceRow key={device.id} device={device} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function DeviceRow({ device }: { device: Device }) {
  return (
    <tr className="bg-gray-950 hover:bg-gray-900/50 transition-colors">
      <td className="px-4 py-3">
        <div>
          <p className="font-medium text-gray-200">{device.hostname}</p>
          <p className="text-xs text-gray-600 font-mono">
            {device.id.slice(0, 8)}...
          </p>
        </div>
      </td>
      <td className="px-4 py-3">
        <div>
          <p className="text-gray-300">{device.platform}</p>
          <p className="text-xs text-gray-600">{device.os_version}</p>
        </div>
      </td>
      <td className="px-4 py-3">
        <span className={`font-mono font-bold ${scoreColor(device.posture_score)}`}>
          {device.posture_score}
        </span>
      </td>
      <td className="px-4 py-3">
        <span
          className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${tierBadgeColor(device.access_tier)}`}
        >
          {device.access_tier}
        </span>
      </td>
      <td className="px-4 py-3">
        {device.attestation_verified ? (
          <span className="text-green-400 text-xs">Verified</span>
        ) : (
          <span className="text-gray-600 text-xs">No</span>
        )}
      </td>
      <td className="px-4 py-3 text-gray-500 text-xs">
        {timeAgo(device.last_seen)}
      </td>
    </tr>
  );
}
