import { useEffect, useRef, useState } from 'react';
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
  Divider,
  FormControlLabel,
  IconButton,
  MenuItem,
  Snackbar,
  Switch,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import {
  Close,
  DeleteOutline,
  DnsOutlined,
  FileDownloadOutlined,
  FileUploadOutlined,
  LanOutlined,
  PlayArrow,
  Refresh,
  Stop,
} from '@mui/icons-material';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { formatDuration, formatNumber } from '@/lib/format';
import type { CaptureStatus } from '@/types';

interface CaptureDialogProps {
  open: boolean;
  status?: CaptureStatus;
  onClose: () => void;
  onChanged: () => void;
}

export function CaptureDialog({ open, status, onClose, onChanged }: CaptureDialogProps) {
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [iface, setIface] = useState('');
  const [bpf, setBpf] = useState('tcp or udp or icmp or icmp6');
  const [promisc, setPromisc] = useState(false);
  const [mirror, setMirror] = useState(false);
  const [busy, setBusy] = useState<'start' | 'stop' | 'mirror' | 'import' | 'export' | 'clear' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [snack, setSnack] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const interfacesQuery = useQuery({
    queryKey: ['interfaces'],
    queryFn: api.listInterfaces,
    enabled: open,
  });

  const dnsQuery = useQuery({
    queryKey: ['dns'],
    queryFn: () => api.listDNS(50),
    enabled: open,
    refetchInterval: open ? 4000 : false,
  });

  useEffect(() => {
    if (!open) return;
    setIface(status?.interface ?? '');
    setBpf(status?.bpf || 'tcp or udp or icmp or icmp6');
    setPromisc(Boolean(status?.promisc));
    setMirror(Boolean(status?.mirror));
    setError(null);
    setMessage(null);
    setBusy(null);
    // 仅在打开时从当前状态初始化，避免每秒状态推送覆盖用户输入。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useEffect(() => {
    if (!open || iface) return;
    const items = interfacesQuery.data ?? [];
    const preferred = items.find((item) => item.default) ?? items.find((item) => !item.loopback) ?? items[0];
    if (preferred) setIface(preferred.name);
  }, [open, iface, interfacesQuery.data]);

  const running = status?.running ?? false;
  const available = status?.available ?? false;

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['capture-status'] });
    await queryClient.invalidateQueries({ queryKey: ['interfaces'] });
    await queryClient.invalidateQueries({ queryKey: ['dns'] });
    await queryClient.invalidateQueries({ queryKey: ['packets'] });
    await queryClient.invalidateQueries({ queryKey: ['system-info'] });
    onChanged();
  };

  const start = async () => {
    setBusy('start');
    setError(null);
    setMessage(null);
    try {
      await api.startCapture(iface, bpf, promisc);
      setMessage('网卡采集已启动');
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const stop = async () => {
    setBusy('stop');
    setError(null);
    setMessage(null);
    try {
      await api.stopCapture();
      setMessage('网卡采集已停止');
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const toggleMirror = async (enabled: boolean) => {
    setMirror(enabled);
    setBusy('mirror');
    setError(null);
    try {
      await api.setCaptureMirror(enabled);
      setMessage(enabled ? '代理镜像已开启：新的代理 Flow 会生成合成 TCP 报文' : '代理镜像已关闭');
      await refresh();
    } catch (cause) {
      setMirror(!enabled);
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const importPcap = async (file: File) => {
    setBusy('import');
    setError(null);
    setMessage(null);
    try {
      const result = await api.importPcap(file);
      setMessage(
        `导入完成：${formatNumber(result.packets)} 个报文、${formatNumber(result.flows)} 条 HTTP Flow、${formatNumber(result.dns)} 条 DNS，用时 ${result.elapsedMs}ms`,
      );
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const exportPcap = async () => {
    setBusy('export');
    setError(null);
    try {
      await api.exportPcap();
      setSnack('PCAP 已导出');
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const clear = async () => {
    setConfirmClear(false);
    setBusy('clear');
    setError(null);
    try {
      const result = await api.clearPackets();
      setMessage(`已清空 ${formatNumber(result.count)} 个报文`);
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pr: 1 }}>
          <Box sx={{ flex: 1, fontSize: 15, fontWeight: 700 }}>网卡采集与 PCAP</Box>
          <Chip
            size="small"
            label={running ? '采集中' : available ? '已就绪' : '不可用'}
            color={running ? 'success' : available ? 'info' : 'default'}
            variant="outlined"
          />
          <Tooltip title="刷新状态">
            <IconButton size="small" onClick={() => void refresh()}>
              <Refresh sx={{ fontSize: 15 }} />
            </IconButton>
          </Tooltip>
          <IconButton size="small" onClick={onClose} aria-label="关闭">
            <Close sx={{ fontSize: 16 }} />
          </IconButton>
        </DialogTitle>

        <DialogContent sx={{ pt: 0.5, pb: 1 }}>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
            {error ? <Alert severity="error">{error}</Alert> : null}
            {message ? <Alert severity="success">{message}</Alert> : null}

            {!available ? (
              <Alert severity="warning" variant="outlined">
                <Typography sx={{ fontSize: 11.5, fontWeight: 650, mb: 0.4 }}>实时网卡抓包不可用</Typography>
                <Typography sx={{ fontSize: 11 }}>{status?.reason || '当前构建未启用 Npcap 实时抓包。'}</Typography>
                <Box component="ul" sx={{ m: 0, mt: 0.75, pl: 2.2, fontSize: 10.5, color: 'text.secondary' }}>
                  {(status?.installHint ?? []).map((hint) => (
                    <li key={hint}>{hint}</li>
                  ))}
                </Box>
              </Alert>
            ) : null}

            <Box sx={{ p: 1.5, borderRadius: 1.5, border: '1px solid', borderColor: 'divider', bgcolor: 'action.hover' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                <LanOutlined sx={{ fontSize: 16, color: running ? 'success.main' : 'text.disabled' }} />
                <Typography className="mono" sx={{ fontSize: 12 }}>
                  {status?.interface || '未选择网卡'}
                </Typography>
                <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>{status?.backend ?? '—'}</Typography>
                <Box sx={{ flex: 1 }} />
                <Typography className="mono" sx={{ fontSize: 10, color: 'text.disabled' }}>
                  {formatNumber(status?.packets ?? 0)} / {formatNumber(status?.capacity ?? 0)} 包
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', gap: 2.5, mt: 1.1, flexWrap: 'wrap' }}>
                <Metric label="速率" value={`${Math.round(status?.rate ?? 0)} pkt/s`} />
                <Metric label="HTTP Flow" value={formatNumber(status?.flows ?? 0)} />
                <Metric label="DNS" value={formatNumber(status?.dns ?? 0)} />
                <Metric label="丢弃/截断" value={`${formatNumber(status?.dropped ?? 0)} / ${formatNumber(status?.truncated ?? 0)}`} />
                <Metric label="运行时长" value={formatDuration((status?.uptimeSec ?? 0) * 1000)} />
              </Box>
              {status?.error ? <Alert severity="warning" sx={{ mt: 1.1, py: 0.25 }}>{status.error}</Alert> : null}
            </Box>

            <Section title="实时网卡抓包">
              <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>
                <Box>
                  <Typography sx={{ fontSize: 9.5, color: 'text.disabled', mb: 0.4 }}>网卡</Typography>
                  <TextField
                    size="small"
                    fullWidth
                    select
                    value={iface}
                    onChange={(event) => setIface(event.target.value)}
                    disabled={running || !available}
                  >
                    {(interfacesQuery.data ?? []).map((item) => (
                      <MenuItem key={item.name} value={item.name}>
                        {item.description || item.name}
                        {item.loopback ? '（loopback）' : ''}
                      </MenuItem>
                    ))}
                  </TextField>
                </Box>
                <Box>
                  <Typography sx={{ fontSize: 9.5, color: 'text.disabled', mb: 0.4 }}>BPF 过滤</Typography>
                  <TextField
                    size="small"
                    fullWidth
                    value={bpf}
                    onChange={(event) => setBpf(event.target.value)}
                    disabled={running}
                    placeholder="tcp or udp or icmp or icmp6"
                  />
                </Box>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <FormControlLabel
                  control={<Switch size="small" checked={promisc} onChange={(event) => setPromisc(event.target.checked)} disabled={running} />}
                  label={<Typography sx={{ fontSize: 11 }}>混杂模式</Typography>}
                />
                <Box sx={{ flex: 1 }} />
                <Button
                  size="small"
                  variant={running ? 'outlined' : 'contained'}
                  color={running ? 'inherit' : 'primary'}
                  disabled={busy !== null || (!running && !available)}
                  startIcon={
                    busy === 'start' || busy === 'stop' ? (
                      <CircularProgress size={12} color="inherit" />
                    ) : running ? (
                      <Stop sx={{ fontSize: 14 }} />
                    ) : (
                      <PlayArrow sx={{ fontSize: 14 }} />
                    )
                  }
                  onClick={() => void (running ? stop() : start())}
                >
                  {running ? '停止采集' : '开始采集'}
                </Button>
              </Box>
            </Section>

            <Divider />

            <Section title="代理镜像">
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <FormControlLabel
                  control={
                    <Switch
                      size="small"
                      checked={mirror}
                      onChange={(event) => void toggleMirror(event.target.checked)}
                      disabled={busy === 'mirror'}
                    />
                  }
                  label={<Typography sx={{ fontSize: 11.5 }}>把代理 Flow 合成为 TCP 报文</Typography>}
                />
                <Box sx={{ flex: 1 }} />
                <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>
                  无需驱动与管理员权限，可用于报文视图与合成 PCAP
                </Typography>
              </Box>
              <Typography sx={{ fontSize: 10.5, color: 'text.disabled' }}>
                开启后，新的代理请求/响应会以合成以太网帧写入报文缓存，并与原 Flow 关联；不会重复生成 HTTP Flow。
              </Typography>
            </Section>

            <Divider />

            <Section title="PCAP 导入与导出">
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
                style={{ display: 'none' }}
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  if (file) void importPcap(file);
                }}
              />
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={busy === 'import' ? <CircularProgress size={12} /> : <FileUploadOutlined sx={{ fontSize: 14 }} />}
                  onClick={() => fileInputRef.current?.click()}
                  disabled={busy !== null || running}
                >
                  导入 PCAP
                </Button>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={busy === 'export' ? <CircularProgress size={12} /> : <FileDownloadOutlined sx={{ fontSize: 14 }} />}
                  onClick={() => void exportPcap()}
                  disabled={busy !== null || !status?.packets}
                >
                  导出 PCAP
                </Button>
                <Box sx={{ flex: 1 }} />
                <Button
                  size="small"
                  color="error"
                  variant="outlined"
                  startIcon={<DeleteOutline sx={{ fontSize: 14 }} />}
                  onClick={() => setConfirmClear(true)}
                  disabled={busy !== null || !status?.packets}
                >
                  清空报文
                </Button>
              </Box>
              <Typography sx={{ fontSize: 10.5, color: 'text.disabled' }}>
                支持经典 pcap（微秒/纳秒时间戳），单文件最大 256MB；pcapng 请先用 Wireshark 转换。导入期间会清空重组状态。
              </Typography>
            </Section>

            <Divider />

            <Section
              title={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <DnsOutlined sx={{ fontSize: 13 }} />
                  DNS 映射
                </Box>
              }
            >
              {(dnsQuery.data ?? []).length === 0 ? (
                <Typography sx={{ fontSize: 10.5, color: 'text.disabled' }}>暂无 DNS 记录。导入含 DNS 的 PCAP 或开启实时采集后显示。</Typography>
              ) : (
                <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, overflow: 'hidden' }}>
                  {(dnsQuery.data ?? []).slice(0, 10).map((entry, index) => (
                    <Box
                      key={`${entry.domain}-${entry.ip}`}
                      sx={{
                        display: 'grid',
                        gridTemplateColumns: '1fr 140px 50px',
                        gap: 1,
                        px: 1,
                        py: 0.55,
                        borderTop: index === 0 ? 'none' : '1px solid',
                        borderColor: 'divider',
                      }}
                    >
                      <Typography sx={{ fontSize: 11, color: 'text.secondary', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {entry.domain}
                      </Typography>
                      <Typography className="mono" sx={{ fontSize: 10, color: 'text.disabled' }}>{entry.ip}</Typography>
                      <Typography className="mono" sx={{ fontSize: 10, color: 'text.disabled', textAlign: 'right' }}>{entry.ttl}s</Typography>
                    </Box>
                  ))}
                </Box>
              )}
            </Section>

            <Alert severity="info" variant="outlined" sx={{ py: 0.25 }}>
              实时抓包需要 Npcap 与相应权限；请只采集你拥有或获授权的流量。默认不开启混杂模式。
            </Alert>
          </Box>
        </DialogContent>

        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={onClose}>关闭</Button>
        </DialogActions>
      </Dialog>

      <ConfirmDialog
        open={confirmClear}
        title="清空全部报文？"
        description="报文缓存、DNS 映射与重组状态会被清空；已生成的 HTTP Flow 仍保留。"
        confirmLabel="清空报文"
        onCancel={() => setConfirmClear(false)}
        onConfirm={() => void clear()}
      />

      <Snackbar
        open={Boolean(snack)}
        autoHideDuration={1800}
        onClose={() => setSnack(null)}
        message={snack}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      />
    </>
  );
}

function Section({ title, children }: { title: React.ReactNode; children: React.ReactNode }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'text.disabled', mb: 0.75 }}>
        {title}
      </Typography>
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.9 }}>{children}</Box>
    </Box>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 9, color: 'text.disabled' }}>{label}</Typography>
      <Typography className="mono" sx={{ fontSize: 10.5, color: 'text.secondary' }}>
        {value}
      </Typography>
    </Box>
  );
}

function messageOf(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  return '操作失败';
}
