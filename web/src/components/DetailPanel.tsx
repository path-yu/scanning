import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  IconButton,
  Skeleton,
  Snackbar,
  Tab,
  Tabs,
  Tooltip,
  Typography,
} from '@mui/material';
import { Close, ContentCopy, Download, Lock, OpenInFull, Replay, Stop } from '@mui/icons-material';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { api } from '@/api';
import { urlOf } from '@/lib/filter';
import { JsonViewerDialog } from '@/components/JsonViewerDialog';
import { ReplayDialog } from '@/components/ReplayDialog';
import {
  formatBytes,
  formatDateTime,
  formatDuration,
  formatTime,
  methodColor,
  prettyBody,
  statusColor,
  statusText,
} from '@/lib/format';
import type { Flow, Message, Timing } from '@/types';

interface DetailPanelProps {
  flowId: string;
  onClose: () => void;
  onSelect: (id: string) => void;
}

export function DetailPanel({ flowId, onClose, onSelect }: DetailPanelProps) {
  const queryClient = useQueryClient();
  const [tab, setTab] = useState(0);
  const [snack, setSnack] = useState<string | null>(null);
  const [replayOpen, setReplayOpen] = useState(false);
  const [resumeBusy, setResumeBusy] = useState(false);

  useEffect(() => {
    setTab(0);
    setReplayOpen(false);
  }, [flowId]);

  const query = useQuery({
    queryKey: ['flow', flowId],
    queryFn: () => api.getFlow(flowId),
    enabled: Boolean(flowId),
    // 请求进行中/暂停时轮询，保证步骤状态及时更新。
    refetchInterval: (q) => {
      const state = q.state.data?.state;
      return state === 'active' || state === 'paused' ? 1200 : false;
    },
  });

  const flow = query.data;
  const url = flow ? urlOf(flow) : '';

  const copy = async (text: string, label = '已复制') => {
    try {
      await navigator.clipboard.writeText(text);
      setSnack(label);
    } catch {
      setSnack('复制失败，请手动选择文本');
    }
  };

  const resume = async (action: 'forward' | 'abort') => {
    if (!flow) return;
    setResumeBusy(true);
    try {
      await api.resumeFlow(flow.id, { action });
      await queryClient.invalidateQueries({ queryKey: ['flow', flow.id] });
      await queryClient.invalidateQueries({ queryKey: ['breakpoints'] });
    } catch (cause) {
      setSnack(cause instanceof Error ? cause.message : '断点操作失败');
    } finally {
      setResumeBusy(false);
    }
  };

  return (
    <Box
      component="aside"
      sx={{
        width: 440,
        minWidth: 370,
        maxWidth: 520,
        flexShrink: 0,
        borderLeft: '1px solid',
        borderColor: 'divider',
        bgcolor: 'background.paper',
        display: { xs: 'none', md: 'flex' },
        flexDirection: 'column',
        minHeight: 0,
      }}
    >
      <Box sx={{ px: 1.5, pt: 1.25, pb: 1, borderBottom: '1px solid', borderColor: 'divider', flexShrink: 0 }}>
        {query.isLoading ? (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CircularProgress size={14} />
            <Skeleton width={180} height={18} />
          </Box>
        ) : flow ? (
          <>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.9, minWidth: 0 }}>
              <Box
                component="span"
                sx={{
                  fontSize: 10,
                  fontWeight: 800,
                  color: methodColor(flow.method),
                  letterSpacing: '0.02em',
                  flexShrink: 0,
                }}
              >
                {flow.method}
              </Box>
              <Box
                component="span"
                className="mono"
                sx={{
                  fontSize: 10.5,
                  fontWeight: 700,
                  color: statusColor(flow.statusCode),
                  flexShrink: 0,
                }}
              >
                {flow.statusCode} {statusText(flow.statusCode)}
              </Box>
              <Box sx={{ flex: 1 }} />
              <Tooltip title="复制 URL">
                <IconButton size="small" onClick={() => void copy(url, 'URL 已复制')}>
                  <ContentCopy sx={{ fontSize: 14 }} />
                </IconButton>
              </Tooltip>
              <IconButton size="small" onClick={onClose} aria-label="关闭详情">
                <Close sx={{ fontSize: 15 }} />
              </IconButton>
            </Box>

            <Tooltip title={url}>
              <Typography
                className="mono"
                sx={{
                  mt: 0.75,
                  fontSize: 10.5,
                  color: 'text.secondary',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {url}
              </Typography>
            </Tooltip>

            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.75 }}>
              <Chip size="small" label={flow.mode === 'pcap' ? '网卡抓包' : '代理抓取'} />
              {flow.client.app ? <Chip size="small" label={flow.client.app} /> : null}
              {flow.tls ? <Chip size="small" label={flow.tls.version || 'TLS'} color="success" variant="outlined" /> : null}
              {flow.replayedFrom ? <Chip size="small" label="重放" color="secondary" variant="outlined" /> : null}
              {flow.state === 'active' ? <Chip size="small" label="进行中" color="info" variant="outlined" /> : null}
              {flow.state === 'paused' ? <Chip size="small" label="断点暂停" color="warning" variant="outlined" /> : null}
              {flow.state === 'failed' ? <Chip size="small" label="失败" color="error" variant="outlined" /> : null}
              {(flow.matchedRules ?? []).map((rule) => (
                <Chip key={rule} size="small" label={rule} color="info" variant="outlined" />
              ))}
            </Box>
          </>
        ) : (
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Typography sx={{ fontSize: 12, color: 'text.secondary' }}>流量已不存在或已被淘汰</Typography>
            <IconButton size="small" onClick={onClose}>
              <Close sx={{ fontSize: 15 }} />
            </IconButton>
          </Box>
        )}
      </Box>

      {flow ? (
        <>
          <Tabs
            value={tab}
            onChange={(_, value: number) => setTab(value)}
            variant="fullWidth"
            sx={{ minHeight: 38, borderBottom: '1px solid', borderColor: 'divider', flexShrink: 0 }}
          >
            <Tab label="概览" />
            <Tab label="请求" />
            <Tab label="响应" />
            <Tab label="耗时" />
          </Tabs>

          <Box sx={{ flex: 1, minHeight: 0, overflow: 'auto', p: 1.5 }}>
            {tab === 0 ? (
              <Overview flow={flow} />
            ) : null}
            {tab === 1 ? (
              <MessageView
                title="请求"
                message={flow.request}
                empty="没有请求信息"
                onCopy={copy}
                flowId={flow.id}
                direction="request"
                eapi={isEapiFlow(flow)}
                extra={
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<ContentCopy sx={{ fontSize: 13 }} />}
                    onClick={() => void copy(toCurl(flow), 'cURL 已复制')}
                    sx={{ height: 26 }}
                  >
                    Copy as cURL
                  </Button>
                }
              />
            ) : null}
            {tab === 2 ? (
              <MessageView
                title="响应"
                message={flow.response}
                empty="没有响应信息"
                onCopy={copy}
                flowId={flow.id}
                direction="response"
                eapi={isEapiFlow(flow)}
              />
            ) : null}
            {tab === 3 ? <TimingView timing={flow.timing} durationMs={flow.durationMs} /> : null}
          </Box>

          <Box
            sx={{
              px: 1.5,
              py: 1,
              borderTop: '1px solid',
              borderColor: 'divider',
              display: 'flex',
              alignItems: 'center',
              gap: 1,
              flexShrink: 0,
            }}
          >
            {flow.state === 'paused' ? (
              <>
                <Button
                  size="small"
                  variant="contained"
                  color="warning"
                  onClick={() => void resume('forward')}
                  disabled={resumeBusy}
                >
                  放行
                </Button>
                <Button
                  size="small"
                  variant="outlined"
                  color="error"
                  startIcon={<Stop sx={{ fontSize: 13 }} />}
                  onClick={() => void resume('abort')}
                  disabled={resumeBusy}
                >
                  中止
                </Button>
              </>
            ) : (
              <Button
                size="small"
                variant="contained"
                startIcon={<Replay sx={{ fontSize: 14 }} />}
                onClick={() => setReplayOpen(true)}
              >
                重放
              </Button>
            )}
            <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>
              {formatDateTime(flow.startedAt)}
            </Typography>
            <Box sx={{ flex: 1 }} />
            <Typography className="mono" sx={{ fontSize: 10, color: 'text.disabled' }}>
              {flow.id.slice(-8)}
            </Typography>
          </Box>
        </>
      ) : null}

      {flow ? (
        <ReplayDialog
          open={replayOpen}
          flow={flow}
          onClose={() => setReplayOpen(false)}
          onReplayed={(replayed) => {
            setReplayOpen(false);
            onSelect(replayed.id);
          }}
        />
      ) : null}

      <Snackbar
        open={Boolean(snack)}
        autoHideDuration={1600}
        onClose={() => setSnack(null)}
        message={snack}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      />
    </Box>
  );
}

function Overview({ flow }: { flow: Flow }) {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
      {flow.error ? (
        <Alert severity="error" variant="outlined">
          {flow.error.stage} / {flow.error.code}: {flow.error.message}
        </Alert>
      ) : null}

      <Section title="基本信息">
        <InfoRow
          label="状态"
          value={
            <Box component="span" sx={{ color: statusColor(flow.statusCode), fontWeight: 700 }}>
              {flow.statusCode} {statusText(flow.statusCode)}
            </Box>
          }
        />
        <InfoRow label="耗时" value={formatDuration(flow.durationMs)} mono />
        <InfoRow label="大小" value={`${formatBytes(flow.reqSize)} ↑ / ${formatBytes(flow.respSize)} ↓`} mono />
        {flow.state !== 'completed' ? <InfoRow label="流程状态" value={flow.state} mono /> : null}
        {flow.matchedRules?.length ? (
          <InfoRow
            label="命中规则"
            value={
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                {flow.matchedRules.map((rule) => (
                  <Chip key={rule} size="small" label={rule} color="info" variant="outlined" />
                ))}
              </Box>
            }
          />
        ) : null}
        {flow.breakpoint ? <InfoRow label="断点" value="曾在此 Flow 暂停等待放行" /> : null}
        <InfoRow label="客户端" value={`${flow.client.ip}:${flow.client.port}${flow.client.app ? ` · ${flow.client.app}` : ''}`} mono />
        <InfoRow label="服务端" value={`${flow.server.ip}:${flow.server.port}`} mono />
        <InfoRow label="开始时间" value={formatDateTime(flow.startedAt)} mono />
        {flow.completedAt ? <InfoRow label="完成时间" value={formatTime(flow.completedAt)} mono /> : null}
        {flow.replayedFrom ? <InfoRow label="重放来源" value={flow.replayedFrom.slice(-8)} mono /> : null}
      </Section>

      {flow.tls ? (
        <Section title="TLS">
          <InfoRow label="版本" value={`${flow.tls.version} · ${flow.tls.cipherSuite}`} mono />
          <InfoRow label="SNI" value={flow.tls.sni} mono />
          <InfoRow label="ALPN" value={flow.tls.alpn || '—'} mono />
          <InfoRow
            label="校验"
            value={
              <Box component="span" sx={{ color: flow.tls.verified ? 'success.main' : 'warning.main' }}>
                {flow.tls.verified ? '通过' : '未校验'}
              </Box>
            }
          />
          {flow.tls.cert ? (
            <>
              <InfoRow label="证书主体" value={flow.tls.cert.subject} mono />
              <InfoRow label="签发者" value={flow.tls.cert.issuer} mono />
              <InfoRow label="有效期" value={`${formatDateTime(flow.tls.cert.notBefore)} → ${formatDateTime(flow.tls.cert.notAfter)}`} mono />
              <InfoRow label="SAN" value={flow.tls.cert.sans.join(', ') || '—'} mono />
            </>
          ) : null}
        </Section>
      ) : null}

      <Section title="备注与标签">
        <InfoRow
          label="标签"
          value={
            (flow.tags ?? []).length ? (
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                {(flow.tags ?? []).map((tag) => <Chip key={tag} size="small" label={tag} />)}
              </Box>
            ) : (
              '—'
            )
          }
        />
        <InfoRow label="备注" value={flow.note || '—'} />
      </Section>
    </Box>
  );
}

function MessageView({
  title,
  message,
  empty,
  onCopy,
  extra,
  flowId,
  direction,
  eapi,
}: {
  title: string;
  message?: Message;
  empty: string;
  onCopy: (text: string, label?: string) => void;
  extra?: ReactNode;
  flowId: string;
  direction: 'request' | 'response';
  eapi?: boolean;
}) {
  if (!message) {
    return <EmptyState text={empty} />;
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Typography sx={{ fontSize: 11, fontWeight: 700, color: 'text.secondary', letterSpacing: '0.04em' }}>
          {title}头
        </Typography>
        <Typography className="mono" sx={{ fontSize: 10, color: 'text.disabled' }}>
          {message.httpVersion}
        </Typography>
        <Box sx={{ flex: 1 }} />
        {extra}
      </Box>

      <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, overflow: 'hidden' }}>
        {message.headers.length ? (
          message.headers.map((header, index) => (
            <Box
              key={`${header.name}-${index}`}
              onClick={() => void onCopy(header.value, `${header.name} 已复制`)}
              sx={{
                display: 'grid',
                gridTemplateColumns: '130px 1fr',
                gap: 1,
                px: 1,
                py: 0.55,
                borderTop: index === 0 ? 'none' : '1px solid',
                borderColor: 'divider',
                cursor: 'pointer',
                '&:hover': { bgcolor: 'action.hover' },
              }}
            >
              <Typography className="mono" sx={{ fontSize: 10, color: 'text.disabled', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {header.name}
              </Typography>
              <Typography className="mono" sx={{ fontSize: 10, color: 'text.secondary', wordBreak: 'break-all' }}>
                {header.value}
              </Typography>
            </Box>
          ))
        ) : (
          <Typography sx={{ p: 1, fontSize: 10.5, color: 'text.disabled' }}>无 Header</Typography>
        )}
      </Box>

      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Typography sx={{ fontSize: 11, fontWeight: 700, color: 'text.secondary', letterSpacing: '0.04em' }}>
          正文
        </Typography>
        {message.body ? (
          <Typography className="mono" sx={{ fontSize: 10, color: 'text.disabled' }}>
            {formatBytes(message.body.size)}
          </Typography>
        ) : null}
        <Box sx={{ flex: 1 }} />
        {message.body?.preview ? (
          <Tooltip title="复制正文">
            <IconButton size="small" onClick={() => void onCopy(message.body?.preview ?? '', '正文已复制')}>
              <ContentCopy sx={{ fontSize: 14 }} />
            </IconButton>
          </Tooltip>
        ) : null}
      </Box>

      <BodyView message={message} flowId={flowId} direction={direction} eapi={eapi} onCopy={onCopy} />
    </Box>
  );
}

const BODY_AUTO_FETCH_LIMIT = 512 * 1024;
const BODY_DECRYPTED_AUTO_FETCH_LIMIT = 2 * 1024 * 1024;
const BODY_RENDER_LIMIT = 512 * 1024;

function isEapiFlow(flow: Flow): boolean {
  const host = (flow.host || '').toLowerCase();
  const path = (flow.path || '').toLowerCase();
  return (host === 'music.163.com' || host.endsWith('.music.163.com')) && path.startsWith('/eapi/');
}

function extensionForMime(mime: string): string {
  const value = (mime || '').toLowerCase();
  if (value.includes('json')) return 'json';
  if (value.includes('html')) return 'html';
  if (value.includes('xml')) return 'xml';
  if (value.includes('javascript')) return 'js';
  if (value.includes('css')) return 'css';
  if (value.includes('csv')) return 'csv';
  if (value.includes('x-www-form-urlencoded')) return 'txt';
  if (value.startsWith('text/')) return 'txt';
  return 'bin';
}

function BodyView({
  message,
  flowId,
  direction,
  eapi,
  onCopy,
}: {
  message: Message;
  flowId: string;
  direction: 'request' | 'response';
  eapi?: boolean;
  onCopy: (text: string, label?: string) => void;
}) {
  const body = message.body;
  const [loadFull, setLoadFull] = useState(false);
  const [jsonOpen, setJsonOpen] = useState(false);
  const [downloadError, setDownloadError] = useState('');

  useEffect(() => {
    setLoadFull(false);
    setJsonOpen(false);
    setDownloadError('');
  }, [flowId, direction]);

  const download = async (raw: boolean, extension: string) => {
    setDownloadError('');
    try {
      await api.downloadFlowBody(flowId, direction, raw, extension);
    } catch (cause) {
      setDownloadError(cause instanceof Error ? cause.message : '下载失败');
    }
  };

  const textual = Boolean(body?.text || body?.decrypted);
  const autoLimit = body?.decrypted ? BODY_DECRYPTED_AUTO_FETCH_LIMIT : BODY_AUTO_FETCH_LIMIT;
  const autoFetch = textual && (body?.size ?? 0) <= autoLimit;
  const bodyQuery = useQuery({
    queryKey: ['body', flowId, direction, 'full'],
    queryFn: () => api.getFlowBody(flowId, direction),
    enabled: textual && (autoFetch || loadFull),
    staleTime: 60_000,
  });

  if (!body) {
    return <EmptyState text="没有正文" compact />;
  }

  if (!textual) {
    return (
      <Box
        sx={{
          border: '1px dashed',
          borderColor: 'divider',
          borderRadius: 1,
          p: 1.25,
          display: 'flex',
          flexDirection: 'column',
          gap: 0.75,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
          <Typography sx={{ fontSize: 11, fontWeight: 650, color: 'text.secondary' }}>
            二进制 / 加密内容
          </Typography>
          <Chip size="small" label="不预览" variant="outlined" sx={{ height: 17, fontSize: 9 }} />
        </Box>
        <Typography className="mono" sx={{ fontSize: 10, color: 'text.disabled', wordBreak: 'break-all' }}>
          {body.mime || 'application/octet-stream'} · {formatBytes(body.size)}
        </Typography>
        <Typography sx={{ fontSize: 10.5, color: 'text.secondary', lineHeight: 1.55 }}>
          {eapi
            ? '该响应为 EAPI 加密正文。点击“下载 JSON”会先解密再保存为 .json 文件。'
            : '响应不是可显示的文本，可能经过协议层加密、压缩或为二进制数据。已停止自动加载，避免界面卡顿和乱码。'}
        </Typography>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
          {eapi ? (
            <Button
              size="small"
              variant="contained"
              startIcon={<Download sx={{ fontSize: 14 }} />}
              onClick={() => void download(false, 'json')}
              sx={{ height: 26 }}
            >
              下载 JSON
            </Button>
          ) : null}
          <Button
            size="small"
            variant="outlined"
            startIcon={<Download sx={{ fontSize: 14 }} />}
            onClick={() => void download(true, 'bin')}
            sx={{ height: 26 }}
          >
            {eapi ? '下载原始密文（.bin）' : '下载原始正文（.bin）'}
          </Button>
          {body.truncated ? (
            <Typography sx={{ fontSize: 9.5, color: 'text.disabled' }}>
              已截断：{formatBytes(body.capturedSize)} / {formatBytes(body.size)}
            </Typography>
          ) : null}
        </Box>
        {downloadError ? (
          <Alert severity="error" variant="outlined" sx={{ py: 0.25 }}>
            下载失败：{downloadError}
          </Alert>
        ) : null}
      </Box>
    );
  }

  const text = bodyQuery.data ?? body.preview ?? '';
  const displayMime = body.decodedMime || body.mime;
  const downloadExt = eapi ? 'json' : extensionForMime(displayMime);
  const pretty = text.length <= 4 * 1024 * 1024 ? prettyBody(text, displayMime) : text;
  const clipped = Boolean(bodyQuery.data && pretty.length > BODY_RENDER_LIMIT);
  const renderedText = clipped ? pretty.slice(0, BODY_RENDER_LIMIT) : pretty;
  const largeUnloaded = !bodyQuery.data && body.size > autoLimit;
  const jsonLike = Boolean(eapi) || /json/i.test(displayMime) || /^[{\[]/.test(text.trimStart());
  const dialogLoading = bodyQuery.isFetching || (!bodyQuery.data && !bodyQuery.isError);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, flexWrap: 'wrap' }}>
        {body.decrypted ? (
          <Chip size="small" label="EAPI 已解密" color="info" variant="outlined" sx={{ height: 17, fontSize: 9 }} />
        ) : null}
        <Chip size="small" label={bodyQuery.data ? '完整正文' : '预览'} variant="outlined" />
        {bodyQuery.isFetching ? <Typography sx={{ fontSize: 9.5, color: 'text.disabled' }}>加载中…</Typography> : null}
        {largeUnloaded && !bodyQuery.isFetching ? (
          <Button size="small" variant="text" sx={{ height: 24, minWidth: 0 }} onClick={() => setLoadFull(true)}>
            {body.decrypted ? '加载完整解密正文' : '加载完整正文'}（{formatBytes(body.size)}）
          </Button>
        ) : null}
        <Box sx={{ flex: 1 }} />
        {jsonLike ? (
          <Button
            size="small"
            variant="text"
            startIcon={<OpenInFull sx={{ fontSize: 13 }} />}
            onClick={() => {
              setJsonOpen(true);
              if (!bodyQuery.data) setLoadFull(true);
            }}
            sx={{ height: 24, minWidth: 0, px: 0.75 }}
          >
            全屏
          </Button>
        ) : null}
        <Button
          size="small"
          variant="text"
          startIcon={<Download sx={{ fontSize: 13 }} />}
          onClick={() => void download(false, downloadExt)}
          sx={{ height: 24, minWidth: 0, px: 0.75 }}
        >
          下载 {downloadExt.toUpperCase()}
        </Button>
        {body.decrypted ? (
          <Tooltip title="下载原始密文（.bin）">
            <IconButton size="small" onClick={() => void download(true, 'bin')}>
              <Lock sx={{ fontSize: 14 }} />
            </IconButton>
          </Tooltip>
        ) : null}
        <Tooltip title={bodyQuery.data ? '复制正文' : '复制预览'}>
          <IconButton size="small" onClick={() => void onCopy(text, bodyQuery.data ? '正文已复制' : '预览已复制')}>
            <ContentCopy sx={{ fontSize: 14 }} />
          </IconButton>
        </Tooltip>
      </Box>
      {body.truncated ? (
        <Alert severity="warning" variant="outlined" sx={{ py: 0.25 }}>
          正文已截断：最多保留 {formatBytes(body.capturedSize)} / {formatBytes(body.size)}
        </Alert>
      ) : null}
      {largeUnloaded ? (
        <Alert severity="info" variant="outlined" sx={{ py: 0.25 }}>
          正文较大（{formatBytes(body.size)}），默认仅显示{body.decrypted ? '解密后的' : ''}预览；可手动加载或下载原始正文。
        </Alert>
      ) : null}
      {clipped ? (
        <Alert severity="warning" variant="outlined" sx={{ py: 0.25 }}>
          正文较大，界面仅渲染前 {formatBytes(BODY_RENDER_LIMIT)}；完整内容请下载。
        </Alert>
      ) : null}
      {bodyQuery.isError ? (
        <Alert severity="error" variant="outlined" sx={{ py: 0.25 }}>
          加载完整正文失败：{bodyQuery.error instanceof Error ? bodyQuery.error.message : '未知错误'}
        </Alert>
      ) : null}
      {downloadError ? (
        <Alert severity="error" variant="outlined" sx={{ py: 0.25 }}>
          下载失败：{downloadError}
        </Alert>
      ) : null}
      <Box
        component="pre"
        className="mono"
        sx={{
          m: 0,
          p: 1.25,
          maxHeight: 360,
          overflow: 'auto',
          fontSize: 10.5,
          lineHeight: 1.7,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          bgcolor: 'action.hover',
          border: '1px solid',
          borderColor: 'divider',
          borderRadius: 1,
          color: 'text.secondary',
        }}
      >
        {renderedText}
      </Box>
      {jsonLike ? (
        <JsonViewerDialog
          open={jsonOpen}
          onClose={() => setJsonOpen(false)}
          title={direction === 'response' ? '响应 JSON' : '请求 JSON'}
          text={bodyQuery.data ?? body.preview ?? ''}
          size={body.size}
          loading={dialogLoading}
          error={
            bodyQuery.isError
              ? `加载完整正文失败：${bodyQuery.error instanceof Error ? bodyQuery.error.message : '未知错误'}`
              : undefined
          }
          decrypted={body.decrypted}
          truncated={body.truncated}
          downloadLabel={`下载 ${downloadExt.toUpperCase()}`}
          onCopy={() => void onCopy(bodyQuery.data ?? text, '正文已复制')}
          onDownload={() => void download(false, downloadExt)}
        />
      ) : null}
    </Box>
  );
}

function TimingView({ timing, durationMs }: { timing?: Timing; durationMs: number }) {
  const segments = useMemo(() => {
    if (!timing) return [];
    return [
      { label: 'DNS', value: timing.dnsMs, color: '#a78bfa' },
      { label: '连接', value: timing.connectMs, color: '#38bdf8' },
      { label: 'TLS', value: timing.tlsMs, color: '#34d399' },
      { label: '发送', value: timing.sendMs, color: '#fbbf24' },
      { label: '等待', value: timing.waitMs, color: '#f97316' },
      { label: '接收', value: timing.receiveMs, color: '#f87171' },
    ].filter((segment) => segment.value > 0);
  }, [timing]);

  if (!timing) {
    return <EmptyState text="没有耗时数据" />;
  }

  const total = segments.reduce((sum, segment) => sum + segment.value, 0) || durationMs || 1;

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
      <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1 }}>
        <Typography sx={{ fontSize: 22, fontWeight: 750, letterSpacing: '-0.03em' }}>
          {formatDuration(durationMs)}
        </Typography>
        <Typography sx={{ fontSize: 10.5, color: 'text.disabled' }}>总耗时</Typography>
      </Box>

      <Box sx={{ display: 'flex', height: 10, borderRadius: 2, overflow: 'hidden', bgcolor: 'action.hover' }}>
        {segments.map((segment) => (
          <Tooltip key={segment.label} title={`${segment.label} ${formatDuration(segment.value)}`}>
            <Box sx={{ width: `${(segment.value / total) * 100}%`, bgcolor: segment.color, opacity: 0.85 }} />
          </Tooltip>
        ))}
      </Box>

      <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, overflow: 'hidden' }}>
        {segments.map((segment, index) => (
          <Box
            key={segment.label}
            sx={{
              display: 'grid',
              gridTemplateColumns: '10px 1fr auto auto',
              alignItems: 'center',
              gap: 1,
              px: 1,
              py: 0.65,
              borderTop: index === 0 ? 'none' : '1px solid',
              borderColor: 'divider',
            }}
          >
            <Box sx={{ width: 7, height: 7, borderRadius: 0.5, bgcolor: segment.color }} />
            <Typography sx={{ fontSize: 11, color: 'text.secondary' }}>{segment.label}</Typography>
            <Typography className="mono" sx={{ fontSize: 10.5, color: 'text.secondary' }}>
              {formatDuration(segment.value)}
            </Typography>
            <Typography className="mono" sx={{ fontSize: 9.5, color: 'text.disabled', width: 38, textAlign: 'right' }}>
              {Math.round((segment.value / total) * 100)}%
            </Typography>
          </Box>
        ))}
      </Box>
    </Box>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Box>
      <Typography
        sx={{
          fontSize: 10,
          fontWeight: 700,
          letterSpacing: '0.08em',
          color: 'text.disabled',
          textTransform: 'uppercase',
          mb: 0.75,
        }}
      >
        {title}
      </Typography>
      <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, overflow: 'hidden' }}>
        {children}
      </Box>
    </Box>
  );
}

function InfoRow({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: '82px 1fr',
        gap: 1,
        px: 1,
        py: 0.65,
        '& + &': { borderTop: '1px solid', borderTopColor: 'divider' },
      }}
    >
      <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>{label}</Typography>
      <Box
        className={mono ? 'mono' : undefined}
        sx={{ fontSize: 10.5, color: 'text.secondary', wordBreak: 'break-all', minWidth: 0 }}
      >
        {value}
      </Box>
    </Box>
  );
}

function EmptyState({ text, compact }: { text: string; compact?: boolean }) {
  return (
    <Box
      sx={{
        display: 'grid',
        placeItems: 'center',
        py: compact ? 1.5 : 3,
        border: '1px dashed',
        borderColor: 'divider',
        borderRadius: 1,
        color: 'text.disabled',
        fontSize: 11,
      }}
    >
      {text}
    </Box>
  );
}

function toCurl(flow: Flow): string {
  const request = flow.request;
  if (!request) return `curl '${urlOf(flow)}'`;
  const parts = [`curl -X ${flow.method} '${urlOf(flow)}'`];
  for (const header of request.headers) {
    parts.push(`  -H '${header.name}: ${header.value.replace(/'/g, `'\\''`)}'`);
  }
  if (request.body?.preview) {
    parts.push(`  --data-raw '${request.body.preview.replace(/'/g, `'\\''`)}'`);
  }
  return parts.join(' \\\n');
}
