import { useState, type ReactNode } from 'react';
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
  IconButton,
  Skeleton,
  Tooltip,
  Typography,
} from '@mui/material';
import { Close, Download, OpenInNew, PlayArrow, Stop } from '@mui/icons-material';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { formatDateTime, formatDuration } from '@/lib/format';
import type { ProxyStatus, SystemProxyConfig } from '@/types';

interface ProxyDialogProps {
  open: boolean;
  proxyStatus?: ProxyStatus;
  onClose: () => void;
  onChanged: () => void;
}

type BusyAction = 'toggle' | 'install' | 'download' | 'regenerate' | 'browser' | 'sysproxy' | null;
type ConfirmSysProxy = 'apply' | 'restore' | null;

export function ProxyDialog({ open, proxyStatus, onClose, onChanged }: ProxyDialogProps) {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState<BusyAction>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmRegenerate, setConfirmRegenerate] = useState(false);
  const [confirmSysProxy, setConfirmSysProxy] = useState<ConfirmSysProxy>(null);

  const proxyQuery = useQuery({
    queryKey: ['proxy-status'],
    queryFn: api.getProxyStatus,
    enabled: open,
    refetchInterval: open ? 2000 : false,
  });
  const certQuery = useQuery({
    queryKey: ['cert-status'],
    queryFn: api.getCertStatus,
    enabled: open,
  });
  const sysProxyQuery = useQuery({
    queryKey: ['system-proxy'],
    queryFn: api.getSystemProxy,
    enabled: open,
  });

  const proxy = proxyQuery.data ?? proxyStatus;
  const cert = certQuery.data;
  const running = proxy?.running ?? false;

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['proxy-status'] });
    await queryClient.invalidateQueries({ queryKey: ['cert-status'] });
    await queryClient.invalidateQueries({ queryKey: ['system-info'] });
    onChanged();
  };

  const toggleProxy = async () => {
    setBusy('toggle');
    setError(null);
    setMessage(null);
    try {
      const next = running ? await api.stopProxy() : await api.startProxy();
      setMessage(next.running ? '代理已启动' : '代理已停止');
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const launchBrowser = async () => {
    setBusy('browser');
    setError(null);
    setMessage(null);
    try {
      const result = await api.launchBrowser();
      setMessage(`已启动抓包浏览器（${result.browser}）：${result.url}`);
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const installCert = async () => {
    setBusy('install');
    setError(null);
    setMessage(null);
    try {
      const result = await api.installCert('user');
      setMessage(result.message);
      if (!result.installed) {
        setError('自动安装未完成，请展开下方命令手动安装，或确认系统策略是否允许导入根证书。');
      }
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const downloadCA = async () => {
    setBusy('download');
    setError(null);
    setMessage(null);
    try {
      await api.downloadCA();
      setMessage('CA 证书已下载');
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const applySystemProxy = async () => {
    setBusy('sysproxy');
    setError(null);
    setMessage(null);
    setConfirmSysProxy(null);
    try {
      const next = await api.applySystemProxy();
      setMessage(next.message || `系统代理已接管为 ${next.appliedProxy}`);
      await queryClient.invalidateQueries({ queryKey: ['system-proxy'] });
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const restoreSystemProxy = async () => {
    setBusy('sysproxy');
    setError(null);
    setMessage(null);
    setConfirmSysProxy(null);
    try {
      await api.restoreSystemProxy();
      setMessage('系统代理已还原为接管前的设置');
      await queryClient.invalidateQueries({ queryKey: ['system-proxy'] });
      await queryClient.invalidateQueries({ queryKey: ['system-info'] });
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const regenerate = async () => {
    setBusy('regenerate');
    setError(null);
    setMessage(null);
    setConfirmRegenerate(false);
    try {
      const result = await api.regenerateCert();
      setMessage(result.message);
      await refresh();
      await certQuery.refetch();
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
          <Box sx={{ flex: 1, fontSize: 15, fontWeight: 700 }}>代理与 HTTPS 证书</Box>
          <IconButton size="small" onClick={onClose} aria-label="关闭">
            <Close sx={{ fontSize: 16 }} />
          </IconButton>
        </DialogTitle>

        <DialogContent sx={{ pt: 0.5, pb: 1 }}>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
            {error ? <Alert severity="error">{error}</Alert> : null}
            {message ? <Alert severity="success">{message}</Alert> : null}

            <Box
              sx={{
                p: 1.5,
                borderRadius: 1.5,
                border: '1px solid',
                borderColor: 'divider',
                bgcolor: 'action.hover',
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Chip
                  size="small"
                  label={running ? '运行中' : proxy?.error ? '启动失败' : '未启动'}
                  color={running ? 'success' : proxy?.error ? 'warning' : 'default'}
                  variant={running ? 'filled' : 'outlined'}
                />
                <Typography className="mono" sx={{ fontSize: 12, color: 'text.primary' }}>
                  {proxy?.addr ?? '127.0.0.1:8899'}
                </Typography>
                <Box sx={{ flex: 1 }} />
                <Tooltip
                  title={
                    running
                      ? '使用独立配置目录启动浏览器，仅该窗口走本代理，不修改系统代理'
                      : '请先启动代理'
                  }
                >
                  <span>
                    <Button
                      size="small"
                      variant="outlined"
                      startIcon={
                        busy === 'browser' ? (
                          <CircularProgress size={12} color="inherit" />
                        ) : (
                          <OpenInNew sx={{ fontSize: 14 }} />
                        )
                      }
                      onClick={() => void launchBrowser()}
                      disabled={!running || busy !== null}
                      sx={{ mr: 0.75 }}
                    >
                      抓包浏览器
                    </Button>
                  </span>
                </Tooltip>
                <Button
                  size="small"
                  variant={running ? 'outlined' : 'contained'}
                  color={running ? 'inherit' : 'primary'}
                  startIcon={
                    busy === 'toggle' ? (
                      <CircularProgress size={12} color="inherit" />
                    ) : running ? (
                      <Stop sx={{ fontSize: 14 }} />
                    ) : (
                      <PlayArrow sx={{ fontSize: 14 }} />
                    )
                  }
                  onClick={() => void toggleProxy()}
                  disabled={busy !== null}
                >
                  {running ? '停止代理' : '启动代理'}
                </Button>
              </Box>

              <Box sx={{ display: 'flex', gap: 2.5, mt: 1.25, flexWrap: 'wrap' }}>
                <Metric label="MITM" value={proxy?.mitm ? '已启用' : '未启用'} />
                <Metric label="上游代理" value={proxy?.upstreamProxy || '直连'} />
                <Metric label="活动连接" value={String(proxy?.connections ?? 0)} />
                <Metric label="运行时长" value={formatDuration((proxy?.uptimeSec ?? 0) * 1000)} />
              </Box>

              {proxy?.error ? (
                <Alert severity="warning" sx={{ mt: 1.25, py: 0.25 }}>
                  {proxy.error}
                </Alert>
              ) : null}
            </Box>

            <Section title="系统代理">
              {sysProxyQuery.isLoading ? (
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>
                  <Skeleton height={20} />
                  <Skeleton height={20} />
                </Box>
              ) : sysProxyQuery.isError ? (
                <Alert severity="error" sx={{ py: 0.25 }}>
                  {messageOf(sysProxyQuery.error)}
                </Alert>
              ) : sysProxyQuery.data && !sysProxyQuery.data.supported ? (
                <Alert severity="info" sx={{ py: 0.25 }}>
                  {sysProxyQuery.data.message || '当前平台暂不支持一键接管系统代理，请手动设置。'}
                </Alert>
              ) : (
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                    <Chip
                      size="small"
                      label={sysProxyQuery.data?.active ? '已接管' : '未接管'}
                      color={sysProxyQuery.data?.active ? 'success' : 'default'}
                      variant={sysProxyQuery.data?.active ? 'filled' : 'outlined'}
                    />
                    <Typography sx={{ fontSize: 11, color: 'text.secondary' }}>
                      当前：{formatSystemProxy(sysProxyQuery.data?.current)}
                    </Typography>
                    <Box sx={{ flex: 1 }} />
                    <Button
                      size="small"
                      variant={sysProxyQuery.data?.active ? 'outlined' : 'contained'}
                      startIcon={busy === 'sysproxy' ? <CircularProgress size={12} color="inherit" /> : undefined}
                      onClick={() => setConfirmSysProxy('apply')}
                      disabled={busy !== null || !running || (sysProxyQuery.data?.active ?? false)}
                    >
                      接管系统代理
                    </Button>
                    <Button
                      size="small"
                      color="warning"
                      variant="outlined"
                      onClick={() => setConfirmSysProxy('restore')}
                      disabled={busy !== null || !(sysProxyQuery.data?.active ?? false)}
                    >
                      还原系统代理
                    </Button>
                  </Box>

                  {sysProxyQuery.data?.backup ? (
                    <Typography sx={{ fontSize: 9.5, color: 'text.disabled' }}>
                      备份：{formatSystemProxy(sysProxyQuery.data.backup)} · {formatDateTime(sysProxyQuery.data.backup.createdAt)}
                    </Typography>
                  ) : null}
                  {sysProxyQuery.data?.message ? (
                    <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>
                      {sysProxyQuery.data.message}
                    </Typography>
                  ) : null}

                  <Alert severity="warning" variant="outlined" sx={{ py: 0.25 }}>
                    接管会写入 Windows 注册表并影响所有应用；退出 Scanning 时会尝试自动还原为备份设置。
                  </Alert>
                </Box>
              )}
            </Section>

            <Section title="三步开始抓包">
              <Step index={1} title="启动代理">
                点击上方「启动代理」，默认监听 <Box component="span" className="mono">127.0.0.1:8899</Box>。
              </Step>
              <Step index={2} title="安装并信任 CA">
                只有客户端信任本工具的根证书，HTTPS 才能被解密。使用下方证书区的「安装到当前用户」或手动命令。
              </Step>
              <Step index={3} title="把流量指向代理">
                <Box component="div" sx={{ mt: 0.5, color: 'text.secondary', fontSize: 11 }}>
                  Windows：设置 → 网络和 Internet → 代理 → 手动设置代理，地址填 <Box component="span" className="mono">127.0.0.1:8899</Box>。
                </Box>
                <Box component="div" sx={{ mt: 0.35, color: 'text.secondary', fontSize: 11 }}>
                  macOS：系统设置 → 网络 → 当前网络 → 详细信息 → 代理。
                </Box>
                <Box component="div" sx={{ mt: 0.35, color: 'text.secondary', fontSize: 11 }}>
                  命令行：
                </Box>
                <Box
                  component="pre"
                  className="mono"
                  sx={{
                    m: 0,
                    mt: 0.5,
                    p: 1,
                    bgcolor: 'background.default',
                    border: '1px solid',
                    borderColor: 'divider',
                    borderRadius: 1,
                    fontSize: 10,
                    color: 'text.secondary',
                    overflow: 'auto',
                  }}
                >
                  {`export HTTPS_PROXY=http://127.0.0.1:8899
export HTTP_PROXY=http://127.0.0.1:8899
curl -x http://127.0.0.1:8899 https://example.com`}
                </Box>
                <Box component="div" sx={{ mt: 0.5, color: 'text.secondary', fontSize: 11 }}>
                  如需经本地 VPN/代理转发，在数据目录 config.yaml 设置 <Box component="span" className="mono">proxy.upstream_proxy</Box> 后重启。
                </Box>
              </Step>
            </Section>

            <Divider />

            <Section title="根证书">
              {certQuery.isLoading || !cert ? (
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>
                  <Skeleton height={20} />
                  <Skeleton height={20} />
                  <Skeleton height={20} />
                </Box>
              ) : (
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                    <Chip
                      size="small"
                      label={cert.installed ? '已信任' : '未信任'}
                      color={cert.installed ? 'success' : 'warning'}
                      variant={cert.installed ? 'filled' : 'outlined'}
                    />
                    <Typography sx={{ fontSize: 11, color: 'text.secondary' }}>
                      {cert.subject}
                    </Typography>
                    <Box sx={{ flex: 1 }} />
                    <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>
                      有效期至 {formatDateTime(cert.notAfter)}
                    </Typography>
                  </Box>

                  <Box
                    sx={{
                      p: 1,
                      bgcolor: 'background.default',
                      border: '1px solid',
                      borderColor: 'divider',
                      borderRadius: 1,
                    }}
                  >
                    <Typography sx={{ fontSize: 9.5, color: 'text.disabled', mb: 0.35 }}>
                      SHA-256 指纹
                    </Typography>
                    <Typography className="mono" sx={{ fontSize: 10, color: 'text.secondary', wordBreak: 'break-all' }}>
                      {cert.fingerprintSha256}
                    </Typography>
                  </Box>

                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    <Button
                      size="small"
                      variant="outlined"
                      startIcon={<Download sx={{ fontSize: 14 }} />}
                      onClick={() => void downloadCA()}
                      disabled={busy !== null}
                    >
                      下载 CA
                    </Button>
                    <Button
                      size="small"
                      variant="contained"
                      onClick={() => void installCert()}
                      disabled={busy !== null}
                      startIcon={busy === 'install' ? <CircularProgress size={12} color="inherit" /> : undefined}
                    >
                      安装到当前用户
                    </Button>
                    <Box sx={{ flex: 1 }} />
                    <Button
                      size="small"
                      color="error"
                      variant="outlined"
                      onClick={() => setConfirmRegenerate(true)}
                      disabled={busy !== null}
                    >
                      重新生成
                    </Button>
                  </Box>

                  {!cert.installed ? (
                    <Alert severity="info" sx={{ py: 0.25 }}>
                      HTTPS 解密要求客户端信任此 CA。Chrome/Edge 使用系统证书库，Firefox 需要在其设置中单独导入。
                    </Alert>
                  ) : null}

                  {cert.manualCommands.length ? (
                    <Box>
                      <Typography sx={{ fontSize: 9.5, color: 'text.disabled', mb: 0.35 }}>
                        手动安装命令（自动安装失败或需要系统级安装时使用）
                      </Typography>
                      <Box
                        component="pre"
                        className="mono"
                        sx={{
                          m: 0,
                          p: 1,
                          maxHeight: 130,
                          overflow: 'auto',
                          bgcolor: 'background.default',
                          border: '1px solid',
                          borderColor: 'divider',
                          borderRadius: 1,
                          fontSize: 9.5,
                          color: 'text.secondary',
                          whiteSpace: 'pre-wrap',
                        }}
                      >
                        {cert.manualCommands.join('\n')}
                      </Box>
                    </Box>
                  ) : null}

                  <Typography sx={{ fontSize: 9.5, color: 'text.disabled' }}>
                    CA 私钥保存在 {cert.caPath.replace(/[\\/][^\\/]+$/, '')}，仅本机可读；重新生成后旧证书立即失效。
                  </Typography>
                </Box>
              )}
            </Section>

            <Alert severity="warning" variant="outlined" sx={{ py: 0.25 }}>
              请只抓取你拥有或获授权的流量。QUIC/HTTP3 与证书固定（Pinning）客户端可能绕过代理或拒绝解密。
            </Alert>
          </Box>
        </DialogContent>

        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={onClose}>关闭</Button>
        </DialogActions>
      </Dialog>

      <ConfirmDialog
        open={confirmRegenerate}
        title="重新生成根证书？"
        description="所有已安装的旧 CA 会立即失效，客户端将出现证书错误，需要重新安装新 CA 并重启相关应用。"
        confirmLabel="重新生成"
        onCancel={() => setConfirmRegenerate(false)}
        onConfirm={() => void regenerate()}
      />

      <ConfirmDialog
        open={confirmSysProxy !== null}
        title={confirmSysProxy === 'apply' ? '接管系统代理？' : '还原系统代理？'}
        description={
          confirmSysProxy === 'apply'
            ? '将把 Windows 系统代理设置为 127.0.0.1:8899，并备份当前设置。所有应用的流量都会经过 Scanning；退出程序时会尝试自动还原。'
            : '将恢复接管前的系统代理设置。'
        }
        confirmLabel={confirmSysProxy === 'apply' ? '接管' : '还原'}
        onCancel={() => setConfirmSysProxy(null)}
        onConfirm={() => {
          if (confirmSysProxy === 'apply') {
            void applySystemProxy();
          } else if (confirmSysProxy === 'restore') {
            void restoreSystemProxy();
          }
        }}
      />
    </>
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
          textTransform: 'uppercase',
          color: 'text.disabled',
          mb: 0.75,
        }}
      >
        {title}
      </Typography>
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>{children}</Box>
    </Box>
  );
}

function Step({ index, title, children }: { index: number; title: string; children: ReactNode }) {
  return (
    <Box sx={{ display: 'flex', gap: 1 }}>
      <Box
        sx={{
          width: 18,
          height: 18,
          borderRadius: '50%',
          bgcolor: 'action.selected',
          color: 'primary.main',
          display: 'grid',
          placeItems: 'center',
          fontSize: 9.5,
          fontWeight: 700,
          flexShrink: 0,
        }}
      >
        {index}
      </Box>
      <Box sx={{ minWidth: 0 }}>
        <Typography sx={{ fontSize: 11.5, fontWeight: 650, color: 'text.primary' }}>{title}</Typography>
        <Box sx={{ fontSize: 11, color: 'text.secondary', mt: 0.25 }}>{children}</Box>
      </Box>
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

function formatSystemProxy(config?: SystemProxyConfig): string {
  if (!config) return '—';
  if (config.proxyEnable !== 1 || !config.proxyServer) {
    return config.autoConfigUrl ? `PAC ${config.autoConfigUrl}` : '未启用（直连）';
  }
  return config.proxyServer + (config.autoConfigUrl ? ` · PAC ${config.autoConfigUrl}` : '');
}

function messageOf(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  return '操作失败';
}
