"use client";

import { useEffect, useState, useCallback } from "react";
import {
  SecurityEvent,
  EventStats,
  fetchEvents,
  fetchEventStats,
  severityColor,
  categoryIcon,
  timeAgo,
} from "@/lib/api";

export default function EventsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [stats, setStats] = useState<EventStats | null>(null);
  const [filter, setFilter] = useState<{
    category?: string;
    min_severity?: string;
  }>({});
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const [evtRes, statsRes] = await Promise.all([
        fetchEvents({ ...filter, limit: 200 }),
        fetchEventStats(),
      ]);
      setEvents(evtRes.events);
      setStats(statsRes);
    } catch {
      // API not reachable — show empty state
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000); // Auto-refresh every 10s
    return () => clearInterval(interval);
  }, [load]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Events</h1>
          <p className="text-sm text-gray-400 mt-1">
            Real-time security event feed from inspection pipeline
          </p>
        </div>
        <button
          onClick={load}
          className="px-3 py-1.5 text-sm bg-gray-800 text-gray-300 rounded hover:bg-gray-700 border border-gray-700"
        >
          Refresh
        </button>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Total Events" value={stats.total} />
          <StatCard
            label="Critical/High"
            value={
              (stats.by_severity["Critical"] || 0) +
              (stats.by_severity["High"] || 0)
            }
            color="text-red-400"
          />
          <StatCard
            label="DLP Alerts"
            value={stats.by_category["DataLoss"] || 0}
            color="text-purple-400"
          />
          <StatCard
            label="C2 Detections"
            value={stats.by_category["CommandAndControl"] || 0}
            color="text-orange-400"
          />
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-3">
        <select
          className="bg-gray-800 text-gray-300 text-sm rounded px-3 py-1.5 border border-gray-700"
          value={filter.category || ""}
          onChange={(e) =>
            setFilter((f) => ({
              ...f,
              category: e.target.value || undefined,
            }))
          }
        >
          <option value="">All Categories</option>
          <option value="DataLoss">Data Loss</option>
          <option value="CommandAndControl">C2 / Beacon</option>
          <option value="DnsThreat">DNS Threat</option>
          <option value="Exfiltration">Exfiltration</option>
          <option value="PolicyViolation">Policy Violation</option>
          <option value="TunnelEvent">Tunnel Event</option>
          <option value="PostureChange">Posture Change</option>
        </select>
        <select
          className="bg-gray-800 text-gray-300 text-sm rounded px-3 py-1.5 border border-gray-700"
          value={filter.min_severity || ""}
          onChange={(e) =>
            setFilter((f) => ({
              ...f,
              min_severity: e.target.value || undefined,
            }))
          }
        >
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High+</option>
          <option value="Medium">Medium+</option>
          <option value="Low">Low+</option>
        </select>
      </div>

      {/* Event List */}
      <div className="space-y-2">
        {loading && (
          <p className="text-gray-500 text-center py-8">Loading events...</p>
        )}
        {!loading && events.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            <p className="text-lg">No events yet</p>
            <p className="text-sm mt-1">
              Events will appear here as the inspection pipeline detects
              threats, DLP violations, and policy events.
            </p>
          </div>
        )}
        {events.map((event) => (
          <EventRow key={event.id} event={event} />
        ))}
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  color = "text-white",
}: {
  label: string;
  value: number;
  color?: string;
}) {
  return (
    <div className="bg-gray-800/50 rounded-lg border border-gray-700 p-4">
      <p className="text-xs text-gray-400 uppercase tracking-wider">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${color}`}>
        {value.toLocaleString()}
      </p>
    </div>
  );
}

function EventRow({ event }: { event: SecurityEvent }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="bg-gray-800/50 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors cursor-pointer"
      onClick={() => setExpanded(!expanded)}
    >
      <div className="px-4 py-3 flex items-center gap-3">
        <span className="text-lg" title={event.category}>
          {categoryIcon(event.category)}
        </span>
        <span
          className={`text-xs font-medium px-2 py-0.5 rounded border ${severityColor(
            event.severity
          )}`}
        >
          {event.severity}
        </span>
        <span className="text-sm text-white flex-1 truncate">
          {event.message}
        </span>
        <span className="text-xs text-gray-500 whitespace-nowrap">
          {event.detector}
        </span>
        <span className="text-xs text-gray-500 whitespace-nowrap">
          {timeAgo(event.timestamp)}
        </span>
        <span
          className={`text-xs px-1.5 py-0.5 rounded ${
            event.outcome === "Blocked"
              ? "bg-red-900/50 text-red-400"
              : event.outcome === "Alerted"
              ? "bg-yellow-900/50 text-yellow-400"
              : "bg-green-900/50 text-green-400"
          }`}
        >
          {event.outcome}
        </span>
      </div>
      {expanded && (
        <div className="px-4 pb-3 border-t border-gray-700 pt-3 grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
          {event.src_ip && (
            <Detail label="Source IP" value={event.src_ip} />
          )}
          {event.dst_ip && (
            <Detail label="Dest IP" value={event.dst_ip} />
          )}
          {event.domain && <Detail label="Domain" value={event.domain} />}
          {event.application && (
            <Detail label="Application" value={event.application} />
          )}
          {event.dst_port && (
            <Detail label="Port" value={String(event.dst_port)} />
          )}
          {event.protocol && (
            <Detail label="Protocol" value={event.protocol} />
          )}
          {event.bytes_out != null && (
            <Detail
              label="Bytes Out"
              value={event.bytes_out.toLocaleString()}
            />
          )}
          {event.bytes_in != null && (
            <Detail
              label="Bytes In"
              value={event.bytes_in.toLocaleString()}
            />
          )}
          {event.device_id && (
            <Detail label="Device ID" value={event.device_id} />
          )}
          {Object.entries(event.metadata).map(([k, v]) => (
            <Detail key={k} label={k} value={v} />
          ))}
          <Detail label="Event ID" value={event.id} />
        </div>
      )}
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-gray-500">{label}: </span>
      <span className="text-gray-300">{value}</span>
    </div>
  );
}
