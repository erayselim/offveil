export type NetworkGroup = {
  id: string;
  label?: string;
  kind: string;
  path: string;
  healthy: boolean;
  checked: boolean;
  unreachable?: boolean;
};

export type NetworkStatus = {
  mode: string;
  coverage: string;
  healthy: boolean;
  reason?: string;
  dpi?: string;
  layers?: { dns: string; tcp: string; tunnel: string };
  groups?: NetworkGroup[] | null;
};

type ConnectionStatus = {
  state: string;
  transition?: string;
  protection: boolean;
  last_error?: string | null;
  network?: NetworkStatus | null;
  tunnel?: { retry_hint?: boolean; up?: boolean } | null;
};

export type ConnectionState =
  | "off" | "connecting" | "reconnecting" | "disconnecting"
  | "limited" | "offline" | "protected" | "broken";

// Protection works but does not cover everything. The last entry is the
// 1.0.4 beta core's local fallback, kept for mixed-version installs.
const LIMITED_REASONS = new Set(["dns_only_fallback", "group_unreachable", "remote_transport_unavailable"]);

export function connectionState(status: ConnectionStatus | null): ConnectionState {
  if (status?.transition === "network_heal") return "reconnecting";
  // A group or provider change keeps the limited path in service; only a
  // replaced gateway (tunnel.up=false) is a real reconnection.
  if (status?.transition === "transport_recovery" &&
    !(isLimitedStatus(status) && status.tunnel?.up !== false)) {
    return "reconnecting";
  }
  if (status?.state === "starting") return "connecting";
  if (status?.state === "stopping") return "disconnecting";
  if (isBrokenStatus(status)) return "broken";
  if (isOfflineStatus(status)) return "offline";
  if (isLimitedStatus(status)) return "limited";
  return status?.protection ? "protected" : "off";
}

export function isLimitedStatus(status: ConnectionStatus | null): boolean {
  return Boolean(
    status?.protection &&
      status.network?.reason &&
      LIMITED_REASONS.has(status.network.reason) &&
      !status.last_error,
  );
}

export function isOfflineStatus(status: ConnectionStatus | null): boolean {
  return Boolean(status?.protection && status.network?.reason === "offline" && !status.last_error);
}

// Broken means the core gave up: the resolver died or a required component
// exhausted its restarts. Limited coverage and a missing internet are not.
export function isBrokenStatus(status: ConnectionStatus | null): boolean {
  if (!status?.protection) return false;
  if (isLimitedStatus(status) || isOfflineStatus(status)) return false;
  if (status.state === "degraded" || status.last_error) return true;
  if (status.network) return false;
  return Boolean(status.tunnel?.retry_hint);
}
