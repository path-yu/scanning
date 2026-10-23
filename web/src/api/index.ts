import type {
  ApiErrorPayload,
  BrowserLaunchResult,
  CaptureStatus,
  CertInstallResult,
  CertStatus,
  DNSEntry,
  DomainStat,
  Envelope,
  Flow,
  FlowSearchResult,
  FlowSummary,
  HookInjectResult,
  HookLog,
  HookProcess,
  HookStatus,
  InterfaceInfo,
  LaunchAppRequest,
  LaunchedApp,
  ListMeta,
  Packet,
  PacketSummary,
  PcapImportResult,
  ProxyStatus,
  RecentApp,
  ReplayOverrides,
  ResumeCommand,
  Rule,
  SavedSession,
  SelfTestResult,
  SessionLoadResult,
  Stats,
  SystemInfo,
  SystemProxyStatus,
} from '@/types';

const BASE = '/api/v1';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;

  constructor(status: number, payload?: ApiErrorPayload, requestId?: string) {
    super(payload?.message || `请求失败（HTTP ${status}）`);
    this.name = 'ApiError';
    this.status = status;
    this.code = payload?.code || 'HTTP_ERROR';
    this.requestId = requestId;
  }
}

async function requestEnvelope<T>(path: string, init: RequestInit = {}): Promise<{ data: T; meta: ListMeta }> {
  const headers = new Headers(init.headers);
  const method = (init.method || 'GET').toUpperCase();
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (!['GET', 'HEAD'].includes(method)) {
    headers.set('X-Scanning-Request', '1');
  }

  const response = await fetch(`${BASE}${path}`, {
    credentials: 'same-origin',
    ...init,
    method,
    headers,
  });

  const text = await response.text();
  let payload: Envelope<T> | undefined;
  if (text) {
    try {
      payload = JSON.parse(text) as Envelope<T>;
    } catch {
      payload = undefined;
    }
  }

  if (!response.ok || payload?.error) {
    throw new ApiError(response.status, payload?.error, payload?.meta?.requestId);
  }
  return {
    data: payload?.data as T,
    meta: payload?.meta ?? {},
  };
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const result = await requestEnvelope<T>(path, init);
  return result.data;
}

export interface ListFlowsParams {
  filter?: string;
  limit?: number;
  cursor?: string;
  order?: 'asc' | 'desc';
  sessionId?: string;
  sinceSeq?: string;
}

export const api = {
  getInfo(): Promise<SystemInfo> {
    return request<SystemInfo>('/system/info');
  },

  getStats(): Promise<Stats> {
    return request<Stats>('/stats');
  },

  runSelfTest(target = ''): Promise<SelfTestResult> {
    return request<SelfTestResult>('/system/selftest', {
      method: 'POST',
      body: JSON.stringify({ target }),
    });
  },

  launchBrowser(url = '', browser = ''): Promise<BrowserLaunchResult> {
    return request<BrowserLaunchResult>('/browser/launch', {
      method: 'POST',
      body: JSON.stringify({ url, browser }),
    });
  },

  listApps(): Promise<LaunchedApp[]> {
    return request<LaunchedApp[]>('/apps');
  },

  listRecentApps(): Promise<RecentApp[]> {
    return request<RecentApp[]>('/apps/recent');
  },

  launchApp(payload: LaunchAppRequest): Promise<LaunchedApp> {
    return request<LaunchedApp>('/apps/launch', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  getHookStatus(): Promise<HookStatus> {
    return request<HookStatus>('/hook/status');
  },

  listHookProcesses(name: string): Promise<HookProcess[]> {
    return request<HookProcess[]>(`/hook/processes?name=${encodeURIComponent(name)}`);
  },

  injectHook(payload: { pid?: number; name?: string; all?: boolean }): Promise<HookInjectResult> {
    return request<HookInjectResult>('/hook/inject', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  getHookLog(lines = 200): Promise<HookLog> {
    return request<HookLog>(`/hook/log?lines=${lines}`);
  },

  getSystemProxy(): Promise<SystemProxyStatus> {
    return request<SystemProxyStatus>('/system/proxy-config');
  },

  applySystemProxy(): Promise<SystemProxyStatus> {
    return request<SystemProxyStatus>('/system/proxy-config/apply', { method: 'POST' });
  },

  restoreSystemProxy(): Promise<SystemProxyStatus> {
    return request<SystemProxyStatus>('/system/proxy-config/restore', { method: 'POST' });
  },

  pickExecutable(): Promise<{ path: string; canceled: boolean }> {
    return request<{ path: string; canceled: boolean }>('/system/pick-file', {
      method: 'POST',
      body: JSON.stringify({ kind: 'executable' }),
    });
  },

  async listFlows(params: ListFlowsParams = {}): Promise<{ flows: FlowSummary[]; meta: ListMeta }> {
    const query = new URLSearchParams();
    query.set('limit', String(params.limit ?? 500));
    query.set('order', params.order ?? 'asc');
    if (params.filter) query.set('filter', params.filter);
    if (params.cursor) query.set('cursor', params.cursor);
    if (params.sessionId) query.set('sessionId', params.sessionId);
    if (params.sinceSeq) query.set('sinceSeq', params.sinceSeq);
    const result = await requestEnvelope<FlowSummary[]>(`/flows?${query.toString()}`);
    return { flows: result.data, meta: result.meta };
  },

  getFlow(id: string): Promise<Flow> {
    return request<Flow>(`/flows/${encodeURIComponent(id)}`);
  },

  searchFlows(
    q: string,
    scope: 'url' | 'request' | 'response' | 'body' | 'all' = 'all',
    signal?: AbortSignal,
  ): Promise<FlowSearchResult> {
    const query = new URLSearchParams({ q, scope });
    return request<FlowSearchResult>(`/flows/search?${query.toString()}`, { signal });
  },

  patchFlow(id: string, patch: { note?: string; tags?: string[]; pinned?: boolean }): Promise<Flow> {
    return request<Flow>(`/flows/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    });
  },

  async getFlowBody(id: string, direction: 'request' | 'response', raw = false): Promise<string> {
    const query = new URLSearchParams({ direction });
    if (raw) query.set('raw', '1');
    const response = await fetch(`${BASE}/flows/${encodeURIComponent(id)}/body?${query.toString()}`, {
      credentials: 'same-origin',
    });
    if (!response.ok) {
      const text = await response.text();
      let payload: Envelope<unknown> | undefined;
      try {
        payload = JSON.parse(text) as Envelope<unknown>;
      } catch {
        payload = undefined;
      }
      throw new ApiError(response.status, payload?.error, payload?.meta?.requestId);
    }
    return response.text();
  },

  downloadFlowBody(
    id: string,
    direction: 'request' | 'response',
    raw = false,
    extension = 'json',
  ): Promise<void> {
    const query = new URLSearchParams({ direction, download: '1' });
    if (raw) query.set('raw', '1');
    return downloadFile(
      `/flows/${encodeURIComponent(id)}/body?${query.toString()}`,
      `flow-${id}-${direction}.${extension}`,
    );
  },

  replayFlow(id: string, overrides: ReplayOverrides = {}): Promise<Flow> {
    return request<Flow>(`/flows/${encodeURIComponent(id)}/replay`, {
      method: 'POST',
      body: JSON.stringify(overrides),
    });
  },

  resumeFlow(id: string, command: ResumeCommand): Promise<{ id: string; resumed: boolean; action: string }> {
    return request<{ id: string; resumed: boolean; action: string }>(
      `/flows/${encodeURIComponent(id)}/resume`,
      { method: 'POST', body: JSON.stringify(command) },
    );
  },

  listBreakpoints(): Promise<FlowSummary[]> {
    return request<FlowSummary[]>('/breakpoints');
  },

  listRules(): Promise<Rule[]> {
    return request<Rule[]>('/rules');
  },

  createRule(rule: Omit<Rule, 'id'>): Promise<Rule> {
    return request<Rule>('/rules', { method: 'POST', body: JSON.stringify(rule) });
  },

  updateRule(id: string, rule: Rule): Promise<Rule> {
    return request<Rule>(`/rules/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(rule),
    });
  },

  deleteRule(id: string): Promise<{ id: string; deleted: boolean }> {
    return request<{ id: string; deleted: boolean }>(`/rules/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },

  async listSessions(): Promise<{ sessions: SavedSession[]; current?: unknown }> {
    const result = await requestEnvelope<SavedSession[]>('/sessions');
    return { sessions: result.data, current: (result.meta as Record<string, unknown>).current };
  },

  saveSession(name: string): Promise<SavedSession> {
    return request<SavedSession>('/sessions', { method: 'POST', body: JSON.stringify({ name }) });
  },

  loadSession(id: string): Promise<SessionLoadResult> {
    return request<SessionLoadResult>(`/sessions/${encodeURIComponent(id)}/load`, { method: 'POST' });
  },

  deleteSession(id: string): Promise<{ id: string; deleted: boolean }> {
    return request<{ id: string; deleted: boolean }>(`/sessions/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },

  demoFlows(count = 10): Promise<{ count: number }> {
    return request<{ count: number }>('/demo/flows', {
      method: 'POST',
      body: JSON.stringify({ count }),
    });
  },

  clearFlows(): Promise<{ count: number }> {
    return request<{ count: number }>('/flows?confirm=true', { method: 'DELETE' });
  },

  deleteFlows(ids: string[]): Promise<{ count: number }> {
    return request<{ count: number }>('/flows?confirm=true', {
      method: 'DELETE',
      body: JSON.stringify({ ids }),
    });
  },

  getDomains(): Promise<DomainStat[]> {
    return request<DomainStat[]>('/domains');
  },

  getProxyStatus(): Promise<ProxyStatus> {
    return request<ProxyStatus>('/proxy/status');
  },

  getCaptureStatus(): Promise<CaptureStatus> {
    return request<CaptureStatus>('/capture/status');
  },

  listInterfaces(): Promise<InterfaceInfo[]> {
    return request<InterfaceInfo[]>('/interfaces');
  },

  startCapture(iface: string, bpf: string, promisc: boolean): Promise<CaptureStatus> {
    return request<CaptureStatus>('/capture/start', {
      method: 'POST',
      body: JSON.stringify({ interface: iface, bpf, promisc }),
    });
  },

  stopCapture(): Promise<CaptureStatus> {
    return request<CaptureStatus>('/capture/stop', { method: 'POST' });
  },

  setCaptureMirror(enabled: boolean): Promise<CaptureStatus> {
    return request<CaptureStatus>('/capture/mirror', {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    });
  },

  importPcap(file: File): Promise<PcapImportResult> {
    return request<PcapImportResult>('/capture/import', {
      method: 'POST',
      headers: { 'Content-Type': file.type || 'application/vnd.tcpdump.pcap' },
      body: file,
    });
  },

  exportPcap(): Promise<void> {
    return downloadFile('/export/pcap', 'scanning.pcap');
  },

  async listPackets(params: {
    protocol?: string;
    q?: string;
    limit?: number;
    cursor?: string;
    order?: 'asc' | 'desc';
  } = {}): Promise<{ packets: PacketSummary[]; meta: ListMeta }> {
    const query = new URLSearchParams();
    query.set('limit', String(params.limit ?? 1000));
    query.set('order', params.order ?? 'desc');
    if (params.protocol) query.set('protocol', params.protocol);
    if (params.q) query.set('q', params.q);
    if (params.cursor) query.set('cursor', params.cursor);
    const result = await requestEnvelope<PacketSummary[]>(`/packets?${query.toString()}`);
    return { packets: result.data, meta: result.meta };
  },

  getPacket(id: string): Promise<Packet> {
    return request<Packet>(`/packets/${encodeURIComponent(id)}`);
  },

  clearPackets(): Promise<{ count: number }> {
    return request<{ count: number }>('/packets?confirm=true', { method: 'DELETE' });
  },

  listDNS(limit = 200): Promise<DNSEntry[]> {
    return request<DNSEntry[]>(`/dns?limit=${limit}`);
  },

  startProxy(): Promise<ProxyStatus> {
    return request<ProxyStatus>('/proxy/start', { method: 'POST' });
  },

  stopProxy(): Promise<ProxyStatus> {
    return request<ProxyStatus>('/proxy/stop', { method: 'POST' });
  },

  getCertStatus(): Promise<CertStatus> {
    return request<CertStatus>('/cert/status');
  },

  installCert(target: 'user' | 'system' = 'user'): Promise<CertInstallResult> {
    return request<CertInstallResult>('/cert/install', {
      method: 'POST',
      body: JSON.stringify({ target }),
    });
  },

  regenerateCert(): Promise<{ status: CertStatus; message: string }> {
    return request<{ status: CertStatus; message: string }>('/cert/regenerate', {
      method: 'POST',
      body: JSON.stringify({ confirm: true }),
    });
  },

  downloadCA(): Promise<void> {
    return downloadFile('/cert/ca', 'scanning-ca.pem');
  },

  exportHar(filter?: string): Promise<void> {
    const query = new URLSearchParams();
    if (filter) query.set('filter', filter);
    const suffix = query.toString() ? `?${query.toString()}` : '';
    return downloadFile(`/export/har${suffix}`, 'scanning.har');
  },
};

async function downloadFile(path: string, fallbackName: string): Promise<void> {
  const response = await fetch(`${BASE}${path}`, { credentials: 'same-origin' });
  if (!response.ok) {
    const text = await response.text();
    let payload: Envelope<unknown> | undefined;
    try {
      payload = JSON.parse(text) as Envelope<unknown>;
    } catch {
      payload = undefined;
    }
    throw new ApiError(response.status, payload?.error, payload?.meta?.requestId);
  }

  const blob = await response.blob();
  const disposition = response.headers.get('Content-Disposition') ?? '';
  const match = /filename="?([^";]+)"?/i.exec(disposition);
  const filename = match?.[1] || fallbackName;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
