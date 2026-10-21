export type NetworkStatus = {
  mode: string;
  coverage: string;
  healthy: boolean;
  reason?: string;
};

type ConnectionStatus = {
  state: string;
  protection: boolean;
  last_error?: string | null;
  network?: NetworkStatus | null;
  tunnel?: { retry_hint?: boolean } | null;
};

export function isLimitedStatus(status: ConnectionStatus | null): boolean {
  return Boolean(
    status?.protection &&
      status.network?.mode === "local" &&
      status.network.reason === "remote_transport_unavailable" &&
      !status.last_error,
  );
}

export function isBrokenStatus(status: ConnectionStatus | null): boolean {
  if (!status?.protection) return false;
  if (isLimitedStatus(status)) return false;
  if (status.state === "degraded" || status.last_error) return true;
  // The core debounces connectivity controls independently of process liveness.
  // A provider retry hint must not replace the accepted network status.
  if (status.network) return false;
  return Boolean(status.tunnel?.retry_hint);
}
