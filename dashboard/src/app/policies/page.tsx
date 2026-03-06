"use client";

import { useEffect, useState } from "react";
import {
  fetchPolicies,
  upsertPolicy,
  deletePolicy,
  actionLabel,
  actionBadgeColor,
  conditionLabel,
  type PolicySet,
  type PolicyRule,
  type Action,
  type Condition,
} from "@/lib/api";

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<PolicySet[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = () => {
    fetchPolicies()
      .then(setPolicies)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const handleDelete = async (name: string) => {
    if (!confirm(`Delete policy "${name}"?`)) return;
    await deletePolicy(name);
    load();
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Policies</h2>
        <div className="flex items-center gap-3">
          <span className="text-sm text-gray-500">{policies.length} policies</span>
          <button
            onClick={() => setShowCreate(!showCreate)}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-colors"
          >
            {showCreate ? "Cancel" : "New Policy"}
          </button>
        </div>
      </div>

      {showCreate && (
        <CreatePolicyForm
          onCreated={() => {
            setShowCreate(false);
            load();
          }}
        />
      )}

      {loading ? (
        <p className="text-gray-500">Loading...</p>
      ) : policies.length === 0 ? (
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-12 text-center">
          <p className="text-gray-500 mb-2">No policies configured yet.</p>
          <p className="text-sm text-gray-600">
            Create a policy to control per-app traffic decisions.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {policies.map((policy) => (
            <PolicyCard
              key={policy.name}
              policy={policy}
              expanded={expanded === policy.name}
              onToggle={() =>
                setExpanded(expanded === policy.name ? null : policy.name)
              }
              onDelete={() => handleDelete(policy.name)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function PolicyCard({
  policy,
  expanded,
  onToggle,
  onDelete,
}: {
  policy: PolicySet;
  expanded: boolean;
  onToggle: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900">
      <div
        className="flex items-center justify-between px-5 py-4 cursor-pointer hover:bg-gray-800/50 transition-colors"
        onClick={onToggle}
      >
        <div className="flex items-center gap-3">
          <span className="text-sm text-gray-500">{expanded ? "▼" : "▶"}</span>
          <div>
            <p className="font-medium text-gray-200">{policy.name}</p>
            <p className="text-xs text-gray-500">
              {policy.rules.length} rule{policy.rules.length !== 1 ? "s" : ""} · Default:{" "}
              <span className="text-gray-400">{actionLabel(policy.default_action)}</span>
            </p>
          </div>
        </div>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onDelete();
          }}
          className="text-xs text-red-500 hover:text-red-400 px-2 py-1 rounded hover:bg-red-900/30 transition-colors"
        >
          Delete
        </button>
      </div>

      {expanded && (
        <div className="border-t border-gray-800 px-5 py-4">
          {policy.rules.length === 0 ? (
            <p className="text-sm text-gray-500">No rules defined.</p>
          ) : (
            <div className="space-y-3">
              {policy.rules.map((rule, i) => (
                <RuleRow key={i} rule={rule} index={i} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function RuleRow({ rule, index }: { rule: PolicyRule; index: number }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950 p-4">
      <div className="flex items-center justify-between mb-2">
        <p className="text-sm font-medium text-gray-300">
          <span className="text-gray-600 mr-2">#{index + 1}</span>
          {rule.name}
        </p>
        <span
          className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${actionBadgeColor(rule.action)}`}
        >
          {actionLabel(rule.action)}
        </span>
      </div>
      <div className="flex flex-wrap gap-2">
        {rule.conditions.map((cond, j) => (
          <span
            key={j}
            className="rounded border border-gray-700 bg-gray-900 px-2 py-0.5 text-xs text-gray-400"
          >
            {conditionLabel(cond)}
          </span>
        ))}
      </div>
    </div>
  );
}

function CreatePolicyForm({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState("");
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [saving, setSaving] = useState(false);
  const [showAddRule, setShowAddRule] = useState(false);

  const handleSave = async () => {
    if (!name.trim()) return;
    setSaving(true);
    try {
      await upsertPolicy({ name, default_action: "Allow", rules });
      onCreated();
    } catch {
      alert("Failed to save policy");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="rounded-lg border border-blue-800 bg-blue-900/10 p-6 mb-6">
      <h3 className="text-sm font-medium text-blue-400 mb-4">New Policy</h3>

      <div className="space-y-4">
        <div>
          <label className="block text-xs text-gray-500 mb-1">Policy Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., block-malware-domains"
            className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600 focus:border-blue-600 focus:outline-none"
          />
        </div>

        {rules.length > 0 && (
          <div className="space-y-2">
            <label className="block text-xs text-gray-500">Rules</label>
            {rules.map((rule, i) => (
              <div
                key={i}
                className="flex items-center justify-between rounded border border-gray-700 bg-gray-900 px-3 py-2"
              >
                <div className="text-sm">
                  <span className="text-gray-300">{rule.name}</span>
                  <span className="text-gray-600 ml-2">
                    ({rule.conditions.length} condition{rule.conditions.length !== 1 ? "s" : ""})
                  </span>
                </div>
                <button
                  onClick={() => setRules(rules.filter((_, j) => j !== i))}
                  className="text-xs text-red-500 hover:text-red-400"
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
        )}

        {showAddRule ? (
          <AddRuleForm
            onAdd={(rule) => {
              setRules([...rules, rule]);
              setShowAddRule(false);
            }}
            onCancel={() => setShowAddRule(false)}
          />
        ) : (
          <button
            onClick={() => setShowAddRule(true)}
            className="text-sm text-blue-400 hover:text-blue-300"
          >
            + Add Rule
          </button>
        )}

        <div className="flex gap-3 pt-2">
          <button
            onClick={handleSave}
            disabled={saving || !name.trim()}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50 transition-colors"
          >
            {saving ? "Saving..." : "Create Policy"}
          </button>
        </div>
      </div>
    </div>
  );
}

function AddRuleForm({
  onAdd,
  onCancel,
}: {
  onAdd: (rule: PolicyRule) => void;
  onCancel: () => void;
}) {
  const [ruleName, setRuleName] = useState("");
  const [actionType, setActionType] = useState<"allow" | "block" | "shadowcopy">("block");
  const [blockReason, setBlockReason] = useState("");
  const [condType, setCondType] = useState<"domain" | "port" | "app" | "tier">("domain");
  const [condValue, setCondValue] = useState("");

  const buildAction = (): Action => {
    switch (actionType) {
      case "allow":
        return "Allow";
      case "block":
        return { Block: { reason: blockReason || "Blocked by policy" } };
      case "shadowcopy":
        return "ShadowCopy";
    }
  };

  const buildCondition = (): Condition | null => {
    if (!condValue.trim()) return null;
    switch (condType) {
      case "domain":
        return { DomainMatches: condValue.split(",").map((s) => s.trim()) };
      case "port":
        return { PortIs: parseInt(condValue, 10) };
      case "app":
        return { ApplicationIs: condValue.trim() };
      case "tier":
        return { AccessTierBelow: condValue.trim() };
    }
  };

  const handleAdd = () => {
    if (!ruleName.trim()) return;
    const cond = buildCondition();
    onAdd({
      name: ruleName,
      conditions: cond ? [cond] : [],
      action: buildAction(),
    });
  };

  return (
    <div className="rounded border border-gray-700 bg-gray-900 p-4 space-y-3">
      <div>
        <label className="block text-xs text-gray-500 mb-1">Rule Name</label>
        <input
          type="text"
          value={ruleName}
          onChange={(e) => setRuleName(e.target.value)}
          placeholder="e.g., block-malware"
          className="w-full rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200 placeholder:text-gray-600 focus:border-blue-600 focus:outline-none"
        />
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs text-gray-500 mb-1">Action</label>
          <select
            value={actionType}
            onChange={(e) => setActionType(e.target.value as typeof actionType)}
            className="w-full rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200 focus:border-blue-600 focus:outline-none"
          >
            <option value="block">Block</option>
            <option value="allow">Allow</option>
            <option value="shadowcopy">Shadow Copy</option>
          </select>
        </div>
        {actionType === "block" && (
          <div>
            <label className="block text-xs text-gray-500 mb-1">Block Reason</label>
            <input
              type="text"
              value={blockReason}
              onChange={(e) => setBlockReason(e.target.value)}
              placeholder="e.g., Malware domain"
              className="w-full rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200 placeholder:text-gray-600 focus:border-blue-600 focus:outline-none"
            />
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs text-gray-500 mb-1">Condition Type</label>
          <select
            value={condType}
            onChange={(e) => setCondType(e.target.value as typeof condType)}
            className="w-full rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200 focus:border-blue-600 focus:outline-none"
          >
            <option value="domain">Domain Matches</option>
            <option value="port">Port Is</option>
            <option value="app">Application Is</option>
            <option value="tier">Access Tier Below</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-gray-500 mb-1">Condition Value</label>
          <input
            type="text"
            value={condValue}
            onChange={(e) => setCondValue(e.target.value)}
            placeholder={
              condType === "domain"
                ? "malware.com, *.evil.net"
                : condType === "port"
                  ? "443"
                  : condType === "app"
                    ? "com.example.app"
                    : "Standard"
            }
            className="w-full rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200 placeholder:text-gray-600 focus:border-blue-600 focus:outline-none"
          />
        </div>
      </div>

      <div className="flex gap-2 pt-1">
        <button
          onClick={handleAdd}
          disabled={!ruleName.trim()}
          className="rounded bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50 transition-colors"
        >
          Add Rule
        </button>
        <button
          onClick={onCancel}
          className="rounded px-3 py-1.5 text-xs text-gray-400 hover:text-gray-200 transition-colors"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
