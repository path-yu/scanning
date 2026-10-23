import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  MenuItem,
  TextField,
  Typography,
} from '@mui/material';
import { Close, CompareArrows, PlayArrow } from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import { diffLines, diffStats } from '@/lib/diff';
import { formatBytes, formatDuration, statusColor, statusText } from '@/lib/format';
import { headersToText, textToHeaders } from '@/lib/rules';
import { urlOf } from '@/lib/filter';
import type { Flow } from '@/types';

interface ReplayDialogProps {
  open: boolean;
  flow: Flow;
  onClose: () => void;
  onReplayed: (flow: Flow) => void;
}

type Tab = 'edit' | 'diff';

export function ReplayDialog({ open, flow, onClose, onReplayed }: ReplayDialogProps) {
  const [tab, setTab] = useState<Tab>('edit');
  const [method, setMethod] = useState(flow.method);
  const [url, setUrl] = useState(urlOf(flow));
  const [headers, setHeaders] = useState('');
  const [body, setBody] = useState('');
  const [initialBody, setInitialBody] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Flow | null>(null);

  useEffect(() => {
    if (!open) return;
    setTab('edit');
    setMethod(flow.method);
    setUrl(urlOf(flow));
    setHeaders(
      headersToText(
        (flow.request?.headers ?? []).filter(
          (header) => !['host', 'content-length', 'connection'].includes(header.name.toLowerCase()),
        ),
      ),
    );
    const text = flow.request?.body?.text ? flow.request.body.preview ?? '' : '';
    setBody(text);
    setInitialBody(text);
    setResult(null);
    setError(null);
    setBusy(false);
    // 仅在打开或切换到另一条 Flow 时重置表单，避免后台刷新覆盖用户编辑。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, flow.id]);

  const originalBodyQuery = useQuery({
    queryKey: ['body', flow.id, 'response', 'full'],
    queryFn: () => api.getFlowBody(flow.id, 'response'),
    enabled: open && Boolean(flow.response?.body?.text),
    staleTime: 60_000,
  });

  const replayedBodyQuery = useQuery({
    queryKey: ['body', result?.id, 'response', 'full'],
    queryFn: () => api.getFlowBody(result!.id, 'response'),
    enabled: Boolean(result?.response?.body?.text),
    staleTime: 60_000,
  });

  const diff = useMemo(() => {
    if (!result) return [];
    const before = originalBodyQuery.data ?? '';
    const after = replayedBodyQuery.data ?? '';
    return diffLines(before, after);
  }, [result, originalBodyQuery.data, replayedBodyQuery.data]);

  const stats = useMemo(() => diffStats(diff), [diff]);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const replayed = await api.replayFlow(flow.id, {
        method,
        url,
        headers: textToHeaders(headers),
        body: body === initialBody && !initialBody ? undefined : body,
      });
      setResult(replayed);
      setTab('diff');
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pr: 1 }}>
        <Box sx={{ flex: 1, fontSize: 15, fontWeight: 700 }}>重放请求</Box>
        {result ? (
          <Chip
            size="small"
            label={`${result.statusCode} ${statusText(result.statusCode)}`}
            sx={{ color: statusColor(result.statusCode), fontWeight: 700 }}
            variant="outlined"
          />
        ) : null}
        <IconButton size="small" onClick={onClose} aria-label="关闭">
          <Close sx={{ fontSize: 16 }} />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ pt: 0.5, pb: 1 }}>
        {error ? <Alert severity="error" sx={{ mb: 1.25 }}>{error}</Alert> : null}

        <Box sx={{ display: 'flex', gap: 0.5, mb: 1.25 }}>
          <Button size="small" variant={tab === 'edit' ? 'contained' : 'text'} onClick={() => setTab('edit')}>
            编辑请求
          </Button>
          <Button
            size="small"
            variant={tab === 'diff' ? 'contained' : 'text'}
            startIcon={<CompareArrows sx={{ fontSize: 14 }} />}
            onClick={() => setTab('diff')}
            disabled={!result}
          >
            响应对比
          </Button>
        </Box>

        {tab === 'edit' ? (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.25 }}>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <TextField
                size="small"
                select
                label="方法"
                value={method}
                onChange={(event) => setMethod(event.target.value)}
                sx={{ width: 130 }}
              >
                {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((item) => (
                  <MenuItem key={item} value={item}>
                    {item}
                  </MenuItem>
                ))}
              </TextField>
              <TextField size="small" fullWidth label="URL" value={url} onChange={(event) => setUrl(event.target.value)} />
            </Box>

            <Box>
              <Typography sx={{ fontSize: 9.5, color: 'text.disabled', mb: 0.4 }}>
                请求 Header（每行 Name: Value）
              </Typography>
              <TextField
                size="small"
                fullWidth
                multiline
                minRows={4}
                value={headers}
                onChange={(event) => setHeaders(event.target.value)}
              />
            </Box>

            <Box>
              <Typography sx={{ fontSize: 9.5, color: 'text.disabled', mb: 0.4 }}>请求正文</Typography>
              <TextField
                size="small"
                fullWidth
                multiline
                minRows={5}
                value={body}
                onChange={(event) => setBody(event.target.value)}
                placeholder={flow.request?.body?.text ? '' : '原请求没有可编辑的文本正文'}
              />
            </Box>

            <Alert severity="info" variant="outlined" sx={{ py: 0.25 }}>
              重放会绕过代理直接访问目标地址，并生成一条新的 Flow；不会应用规则与断点。
            </Alert>
          </Box>
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.25 }}>
            {result ? (
              <>
                <Box
                  sx={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
                    gap: 1,
                    p: 1.25,
                    border: '1px solid',
                    borderColor: 'divider',
                    borderRadius: 1,
                  }}
                >
                  <Metric
                    label="状态"
                    before={`${flow.statusCode} ${statusText(flow.statusCode)}`}
                    after={`${result.statusCode} ${statusText(result.statusCode)}`}
                    afterColor={statusColor(result.statusCode)}
                  />
                  <Metric label="耗时" before={formatDuration(flow.durationMs)} after={formatDuration(result.durationMs)} />
                  <Metric label="大小" before={formatBytes(flow.respSize)} after={formatBytes(result.respSize)} />
                </Box>

                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography sx={{ fontSize: 11, fontWeight: 700, color: 'text.secondary' }}>响应正文 Diff</Typography>
                  {diff.length ? (
                    <>
                      <Chip size="small" label={`+${stats.added}`} color="success" variant="outlined" />
                      <Chip size="small" label={`-${stats.removed}`} color="error" variant="outlined" />
                    </>
                  ) : (
                    <Chip size="small" label="无差异" variant="outlined" />
                  )}
                  <Box sx={{ flex: 1 }} />
                  <Button size="small" onClick={() => onReplayed(result)}>
                    查看新流量
                  </Button>
                </Box>

                {!flow.response?.body?.text ? (
                  <Alert severity="info" variant="outlined" sx={{ py: 0.25 }}>
                    原始响应不是文本，仅对比状态与大小。
                  </Alert>
                ) : originalBodyQuery.isLoading || replayedBodyQuery.isLoading ? (
                  <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
                    <CircularProgress size={18} />
                  </Box>
                ) : (
                  <Box
                    component="pre"
                    className="mono"
                    sx={{
                      m: 0,
                      p: 1.25,
                      maxHeight: 360,
                      overflow: 'auto',
                      fontSize: 10.5,
                      lineHeight: 1.65,
                      bgcolor: 'action.hover',
                      border: '1px solid',
                      borderColor: 'divider',
                      borderRadius: 1,
                    }}
                  >
                    {diff.map((line, index) => (
                      <Box
                        component="span"
                        key={index}
                        sx={{
                          display: 'block',
                          px: 0.5,
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word',
                          color:
                            line.kind === 'add' ? 'success.main' : line.kind === 'remove' ? 'error.main' : 'text.secondary',
                          bgcolor:
                            line.kind === 'add'
                              ? 'rgba(52,211,153,0.08)'
                              : line.kind === 'remove'
                                ? 'rgba(248,113,113,0.08)'
                                : 'transparent',
                        }}
                      >
                        {line.kind === 'add' ? '+ ' : line.kind === 'remove' ? '- ' : '  '}
                        {line.text}
                      </Box>
                    ))}
                  </Box>
                )}
              </>
            ) : (
              <Box sx={{ py: 3, textAlign: 'center', color: 'text.disabled', fontSize: 12 }}>
                执行重放后可在这里对比响应差异。
              </Box>
            )}
          </Box>
        )}
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose}>关闭</Button>
        {tab === 'edit' ? (
          <Button
            variant="contained"
            startIcon={busy ? <CircularProgress size={12} color="inherit" /> : <PlayArrow sx={{ fontSize: 15 }} />}
            onClick={() => void run()}
            disabled={busy}
          >
            发送重放
          </Button>
        ) : null}
      </DialogActions>
    </Dialog>
  );
}

function Metric({
  label,
  before,
  after,
  afterColor,
}: {
  label: string;
  before: string;
  after: string;
  afterColor?: string;
}) {
  return (
    <Box>
      <Typography sx={{ fontSize: 9, color: 'text.disabled' }}>{label}</Typography>
      <Typography className="mono" sx={{ fontSize: 10.5, color: 'text.disabled', mt: 0.35 }}>
        {before}
      </Typography>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mt: 0.2 }}>
        <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>→</Typography>
        <Typography className="mono" sx={{ fontSize: 11, fontWeight: 700, color: afterColor ?? 'text.primary' }}>
          {after}
        </Typography>
      </Box>
    </Box>
  );
}

function messageOf(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  return '重放失败';
}
