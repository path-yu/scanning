export type Mode = 'proxy' | 'pcap' | 'mixed';

export type FlowState =
  | 'pending'
  | 'active'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'canceled'
  | 'aborted';

export interface Header {
  name: string;
  value: string;
}

export interface Body {
  ref: string;
  size: number;
  capturedSize: number;
  truncated: boolean;
  mime: string;
  encoding: string;
  text: boolean;
  preview?: string;
  decrypted?: boolean;
  decodedMime?: string;
}

export interface Message {
  httpVersion: string;
  headers: Header[];
  trailers?: Header[];
  body?: Body;
}

export interface ClientInfo {
  ip: string;
  port: number;
  app?: string;
  pid?: number;
  appPath?: string;
  origin?: string;
}

export interface ServerInfo {
  ip: string;
  port: number;
  name?: string;
}

export interface Certificate {
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  sans: string[];
}

export interface TLSInfo {
  version: string;
  cipherSuite: string;
  sni: string;
  alpn: string;
  verified: boolean;
  cert?: Certificate;
}

export interface Timing {
  dnsMs: number;
  connectMs: number;
  tlsMs: number;
  sendMs: number;
  waitMs: number;
  receiveMs: number;
  totalMs: number;
}

export interface FlowError {
  stage: string;
  code: string;
  message: string;
}

export interface FlowSummary {
  id: string;
  sessionId: string;
  seq: number;
  mode: Mode;
  state: FlowState;
  scheme: string;
  host: string;
  port: number;
  method: string;
  path: string;
  statusCode: number;
  mime: string;
  reqSize: number;
  respSize: number;
  durationMs: number;
  client: ClientInfo;
  tls?: TLSInfo;
  tags: string[];
  pinned: boolean;
  startedAt: string;
  matchedRules?: string[];
  breakpoint?: boolean;
}

export interface FlowSearchResult {
  query: string;
  ids: string[];
  count: number;
  scanned: number;
  truncated?: boolean;
}

export interface Flow extends FlowSummary {
  server: ServerInfo;
  request?: Message;
  response?: Message;
  timing?: Timing;
  error?: FlowError;
  note?: string;
  replayedFrom?: string;
  completedAt?: string;
}

export interface SessionInfo {
  id: string;
  name: string;
  mode: Mode;
  filter: string;
  createdAt: string;
  endedAt?: string;
  flowCount: number;
  byteCount: number;
  persistent: boolean;
}

export interface SavedSession {
  id: string;
  name: string;
  mode: Mode;
  filter: string;
  createdAt: string;
  endedAt?: string;
  flowCount: number;
  byteCount: number;
  savedAt: string;
  persistent: boolean;
}

export type RulePhase = 'request' | 'response';

export type RuleActionType =
  | 'mock'
  | 'block'
  | 'delay'
  | 'map_remote'
  | 'rewrite_request'
  | 'rewrite_response'
  | 'pause';

export interface RuleMatch {
  methods?: string[];
  host?: string;
  path?: string;
  status?: string;
  mime?: string;
  headerName?: string;
  headerValue?: string;
  bodyContains?: string;
}

export interface RuleAction {
  type: RuleActionType;
  status?: number;
  headers?: Header[];
  removeHeaders?: string[];
  body?: string;
  delayMs?: number;
  remote?: string;
  method?: string;
  path?: string;
}

export interface Rule {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  phase: RulePhase;
  stop: boolean;
  match: RuleMatch;
  actions: RuleAction[];
  createdAt?: string;
  updatedAt?: string;
}

export interface ReplayOverrides {
  method?: string;
  url?: string;
  headers?: Header[];
  body?: string;
}

export interface ResumeCommand {
  action: 'forward' | 'abort' | 'mock';
  status?: number;
  headers?: Header[];
  body?: string;
  method?: string;
  path?: string;
}

export interface SessionLoadResult {
  session: SessionInfo;
  count: number;
}

export interface TCPMeta {
  seq: number;
  ack: number;
  flags: string;
  window: number;
  mss?: number;
}

export interface DNSMeta {
  id: number;
  qr: 'query' | 'response' | string;
  question: string;
  qtype: string;
  rcode: string;
  answers?: string[];
  cnames?: string[];
  ttl?: number;
}

export interface TLSMeta {
  recordType: string;
  version: string;
  sni?: string;
  alpn?: string[];
}

export interface PacketSummary {
  id: string;
  sessionId: string;
  no: number;
  timestamp: string;
  captureLen: number;
  origLen: number;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  kind?: string;
  summary: string;
  host?: string;
  flowId?: string;
}

export interface Packet extends PacketSummary {
  tcp?: TCPMeta;
  dns?: DNSMeta;
  tls?: TLSMeta;
  payload?: string;
}

export interface InterfaceInfo {
  name: string;
  description: string;
  addresses: string[];
  loopback: boolean;
  default: boolean;
}

export interface CaptureStatus {
  running: boolean;
  available: boolean;
  backend: string;
  reason?: string;
  interface?: string;
  bpf?: string;
  promisc: boolean;
  mirror: boolean;
  packets: number;
  capacity: number;
  flows: number;
  dns: number;
  dropped: number;
  truncated: number;
  rate: number;
  uptimeSec: number;
  error?: string;
  linkType: number;
  installHint?: string[];
}

export interface PcapImportResult {
  packets: number;
  flows: number;
  dns: number;
  bytes: number;
  elapsedMs: number;
}

export interface DNSEntry {
  ip: string;
  domain: string;
  ttl: number;
  seenAt: string;
  expiresAt: string;
}

export interface StoreStats {
  count: number;
  capacity: number;
  bytes: number;
  evicted: number;
}

export interface ProxyStatus {
  running: boolean;
  addr: string;
  mitm: boolean;
  upstreamProxy?: string;
  connections: number;
  uptimeSec: number;
  error?: string;
  passthrough?: string[];
}

export interface SystemProxyConfig {
  proxyEnable: number;
  proxyServer: string;
  proxyOverride: string;
  autoConfigUrl: string;
}

export interface SystemProxyBackup extends SystemProxyConfig {
  appliedProxy: string;
  createdAt: string;
  active: boolean;
}

export interface SystemProxyStatus {
  platform: string;
  supported: boolean;
  current: SystemProxyConfig;
  backup?: SystemProxyBackup;
  active: boolean;
  appliedProxy?: string;
  updatedAt: string;
  message?: string;
}

export interface CertStatus {
  subject: string;
  serialNumber: string;
  fingerprintSha256: string;
  thumbprintSha1: string;
  notBefore: string;
  notAfter: string;
  caPath: string;
  platform: string;
  installed: boolean;
  installTargets: string[];
  manualCommands: string[];
}

export interface CertInstallResult {
  installed: boolean;
  message: string;
  commands?: string[];
  status: CertStatus;
}

export interface BrowserLaunchResult {
  browser: string;
  executable: string;
  profileDir: string;
  url: string;
}

export type LaunchedAppStatus = 'running' | 'exited' | 'failed';

export interface AppEndpoint {
  address: string;
  port: number;
  count: number;
}

export type AppDiagnosisStatus = 'checking' | 'proxy' | 'direct' | 'unknown' | 'exited';

export interface AppDiagnosis {
  status: AppDiagnosisStatus;
  checkedAt: string;
  flows?: number;
  proxied?: number;
  direct?: AppEndpoint[];
  message: string;
}

export interface LaunchInjection {
  attempted: boolean;
  injected: number;
  failed: number;
  message: string;
  results?: HookProcess[];
}

export interface LaunchedApp {
  id: string;
  name: string;
  path: string;
  args?: string[];
  cwd?: string;
  pid: number;
  status: LaunchedAppStatus;
  exitCode?: number;
  startedAt: string;
  endedAt?: string;
  logPath?: string;
  error?: string;
  diagnosis?: AppDiagnosis;
  injection?: LaunchInjection;
}

export interface RecentApp {
  name: string;
  path: string;
  args?: string[];
  cwd?: string;
  pid?: number;
  status?: LaunchedAppStatus;
  exitCode?: number;
  endedAt?: string;
  error?: string;
  lastLaunchedAt: string;
}

export interface LaunchAppRequest {
  path: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  chromiumFlags?: boolean;
  logOutput?: boolean;
  skipInject?: boolean;
}

export interface HookProcess {
  pid: number;
  name: string;
  path?: string;
  arch?: 'x64' | 'x86' | string;
  dll?: string;
  injected: boolean;
  injectedAt?: string;
  message?: string;
  error?: string;
}

export interface HookStatus {
  supported: boolean;
  dllPath: string;
  dllExists: boolean;
  dllPathX86: string;
  dllExistsX86: boolean;
  proxyAddr: string;
  ports: number[];
  logPath: string;
  injected: HookProcess[];
  message?: string;
}

export interface HookInjectResult {
  results: HookProcess[];
  status: HookStatus;
}

export interface HookLog {
  path: string;
  text: string;
}

export type SelfTestStepStatus = 'pass' | 'fail' | 'skip';

export interface SelfTestStep {
  name: string;
  label: string;
  status: SelfTestStepStatus;
  ms: number;
  detail: string;
}

export interface SelfTestResult {
  ok: boolean;
  target: string;
  proxyAddr: string;
  proxyRunning: boolean;
  mitm: boolean;
  certInstalled: boolean;
  steps: SelfTestStep[];
  totalMs: number;
  finishedAt: string;
}

export interface SystemInfo {
  version: string;
  platform: string;
  dataDir: string;
  dev: boolean;
  headless: boolean;
  session: SessionInfo;
  proxy: ProxyStatus;
  capture: CaptureStatus;
  capabilities: Record<string, boolean>;
  demo: {
    enabled: boolean;
    seed: number;
  };
  ui: {
    embedded: boolean;
  };
  store: StoreStats;
}

export interface Stats {
  flows: number;
  capacity: number;
  bytes: number;
  evicted: number;
  wsClients: number;
  memoryBytes: number;
  uptimeSec: number;
  qps: number;
  sessionId: string;
}

export interface DomainStat {
  host: string;
  count: number;
  bytes: number;
  errors: number;
  methods: Record<string, number>;
}

export interface ListMeta {
  nextCursor?: string;
  hasMore?: boolean;
  total?: number;
  limit?: number;
  order?: 'asc' | 'desc';
  requestId?: string;
}

export interface ApiErrorPayload {
  code: string;
  message: string;
  details?: unknown;
}

export interface Envelope<T> {
  data?: T;
  meta?: ListMeta;
  error?: ApiErrorPayload;
}

export interface WsEvent {
  v: 1;
  type: string;
  seq: number;
  ts: string;
  sessionId: string;
  data?: unknown;
}
