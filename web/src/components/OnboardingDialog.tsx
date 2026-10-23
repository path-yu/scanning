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
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Typography,
} from '@mui/material';
import {
  CheckCircle,
  Close,
  Download,
  ErrorOutline,
  NetworkCheck,
  OpenInNew,
  PlayArrow,
  RemoveCircleOutline,
} from '@mui/icons-material';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api';
import type { SelfTestResult, SelfTestStepStatus } from '@/types';

interface OnboardingDialogProps {
  open: boolean;
  onClose: () => void;
  onChanged: () => void;
  onOpenProxy: () => void;
}

type BusyAction = 'proxy' | 'install' | 'download' | 'selftest' | 'browser' | null;

export function OnboardingDialog({ open, onClose, onChanged, onOpenProxy }: OnboardingDialogProps) {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState<BusyAction>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SelfTestResult | null>(null);

  const proxyQuery = useQuery({
    queryKey: ['proxy-status'],
    queryFn: api.getProxyStatus,
    enabled: open,
  });
  const certQuery = useQuery({
    queryKey: ['cert-status'],
    queryFn: api.getCertStatus,
    enabled: open,
  });

  const proxy = proxyQuery.data;
  const cert = certQuery.data;
  const proxyRunning = proxy?.running ?? false;
  const certInstalled = cert?.installed ?? false;

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['proxy-status'] });
    await queryClient.invalidateQueries({ queryKey: ['cert-status'] });
    await queryClient.invalidateQueries({ queryKey: ['system-info'] });
    onChanged();
  };

  const startProxy = async () => {
    setBusy('proxy');
    setError(null);
    setMessage(null);
    try {
      const next = await api.startProxy();
      setMessage(next.running ? '代理已启动，可以继续配置证书。' : '代理未启动，请查看错误信息。');
      await refresh();
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
      const installed = await api.installCert('user');
      setMessage(installed.message);
      if (!installed.installed) {
        setError('自动安装未完成，可在「代理与证书」中查看手动安装命令。');
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
      setMessage('CA 证书已下载，可手动导入到浏览器或系统证书库。');
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const openBrowser = async () => {
    setBusy('browser');
    setError(null);
    setMessage(null);
    try {
      const launched = await api.launchBrowser();
      setMessage(`已启动抓包浏览器（${launched.browser}）：${launched.url}`);
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const runSelfTest = async () => {
    setBusy('selftest');
    setError(null);
    setMessage(null);
    try {
      const next = await api.runSelfTest();
      setResult(next);
      if (next.ok) {
        setMessage('自检通过：DNS、代理、TLS 解密与 HTTPS 请求均正常。');
      }
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pr: 1 }}>
        <Box sx={{ flex: 1, fontSize: 15, fontWeight: 700 }}>快速开始</Box>
        <IconButton size="small" onClick={onClose} aria-label="关闭快速开始">
          <Close sx={{ fontSize: 16 }} />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ pt: 0.5, pb: 1 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.25 }}>
          <Alert severity="info" sx={{ py: 0.35 }}>
            首次使用建议按顺序完成下面三步；随时可以点击顶栏帮助按钮重新打开。
          </Alert>

          {error ? <Alert severity="error">{error}</Alert> : null}
          {message ? <Alert severity="success">{message}</Alert> : null}

          <StepCard
            index={1}
            title="启动本地代理"
            done={proxyRunning}
            description={
              <>
                代理监听 <Box component="span" className="mono">127.0.0.1:8899</Box>，负责转发并记录 HTTP/HTTPS 流量。
                {proxy?.error ? ` 当前错误：${proxy.error}` : ''}
              </>
            }
            action={
              <Button
                size="small"
                variant={proxyRunning ? 'outlined' : 'contained'}
                startIcon={busy === 'proxy' ? <CircularProgress size={12} color="inherit" /> : <PlayArrow sx={{ fontSize: 14 }} />}
                onClick={() => void startProxy()}
                disabled={proxyRunning || busy !== null}
              >
                {proxyRunning ? '已启动' : '启动代理'}
              </Button>
            }
          />

          <StepCard
            index={2}
            title="安装并信任根证书"
            done={certInstalled}
            description={
              <>
                只有客户端信任本工具 CA，HTTPS 才能被解密。
                {cert ? ` 当前证书：${cert.subject}` : ' 正在读取证书状态…'}
              </>
            }
            action={
              <Box sx={{ display: 'flex', gap: 0.75 }}>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<Download sx={{ fontSize: 14 }} />}
                  onClick={() => void downloadCA()}
                  disabled={busy !== null}
                >
                  {busy === 'download' ? '下载中…' : '下载 CA'}
                </Button>
                <Button
                  size="small"
                  variant={certInstalled ? 'outlined' : 'contained'}
                  onClick={() => void installCert()}
                  disabled={certInstalled || busy !== null}
                  startIcon={busy === 'install' ? <CircularProgress size={12} color="inherit" /> : undefined}
                >
                  {certInstalled ? '已信任' : '安装到当前用户'}
                </Button>
              </Box>
            }
          />

          <StepCard
            index={3}
            title="运行连通性自检"
            done={result?.ok ?? false}
            description={
              <>
                通过代理发起一次真实的 HTTPS 请求，验证 DNS、代理端口、TLS 解密与 HTTP 往返。
                {result ? ` 目标：${result.target}，总耗时 ${result.totalMs} ms。` : ''}
              </>
            }
            action={
              <Button
                size="small"
                variant={result?.ok ? 'outlined' : 'contained'}
                startIcon={
                  busy === 'selftest' ? <CircularProgress size={12} color="inherit" /> : <NetworkCheck sx={{ fontSize: 14 }} />
                }
                onClick={() => void runSelfTest()}
                disabled={busy !== null}
              >
                {result?.ok ? '重新自检' : '运行自检'}
              </Button>
            }
          >
            {result ? (
              <Box
                sx={{
                  mt: 0.75,
                  p: 1,
                  borderRadius: 1,
                  border: '1px solid',
                  borderColor: 'divider',
                  bgcolor: 'background.default',
                }}
              >
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                  <Chip
                    size="small"
                    label={result.ok ? '自检通过' : '自检失败'}
                    color={result.ok ? 'success' : 'error'}
                    variant={result.ok ? 'filled' : 'outlined'}
                    sx={{ height: 18, fontSize: 9.5 }}
                  />
                  <Typography sx={{ fontSize: 9.5, color: 'text.disabled' }}>
                    代理 {result.proxyAddr} · MITM {result.mitm ? '已启用' : '未启用'} · CA{' '}
                    {result.certInstalled ? '已安装' : '未安装'}
                  </Typography>
                </Box>
                <List dense disablePadding>
                  {result.steps.map((step) => (
                    <ListItem key={step.name} disableGutters sx={{ py: 0.15, alignItems: 'flex-start' }}>
                      <ListItemIcon sx={{ minWidth: 22, mt: 0.2 }}>
                        <StepIcon status={step.status} />
                      </ListItemIcon>
                      <ListItemText
                        primary={step.label}
                        secondary={step.detail}
                        primaryTypographyProps={{ sx: { fontSize: 10.5, fontWeight: 650, color: 'text.primary' } }}
                        secondaryTypographyProps={{ sx: { fontSize: 9.5, color: 'text.secondary' } }}
                      />
                      {step.status !== 'skip' ? (
                        <Typography className="mono" sx={{ fontSize: 9, color: 'text.disabled', ml: 1, mt: 0.3 }}>
                          {step.ms} ms
                        </Typography>
                      ) : null}
                    </ListItem>
                  ))}
                </List>
              </Box>
            ) : null}
          </StepCard>

          <Divider />

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
            <Typography sx={{ fontSize: 10, color: 'text.disabled', flex: 1, minWidth: 180 }}>
              自检需要能访问外网；离线环境可改用导入 PCAP 分析已有流量。
            </Typography>
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
              onClick={() => void openBrowser()}
              disabled={!proxyRunning || busy !== null}
            >
              启动抓包浏览器
            </Button>
            <Button size="small" variant="text" onClick={onOpenProxy}>
              打开代理与证书配置
            </Button>
          </Box>
        </Box>
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose}>稍后设置</Button>
      </DialogActions>
    </Dialog>
  );
}

function StepIcon({ status }: { status: SelfTestStepStatus }) {
  if (status === 'pass') {
    return <CheckCircle sx={{ fontSize: 14, color: 'success.main' }} aria-label="通过" />;
  }
  if (status === 'fail') {
    return <ErrorOutline sx={{ fontSize: 14, color: 'error.main' }} aria-label="失败" />;
  }
  return <RemoveCircleOutline sx={{ fontSize: 14, color: 'text.disabled' }} aria-label="跳过" />;
}

interface StepCardProps {
  index: number;
  title: string;
  done: boolean;
  description: ReactNode;
  action: ReactNode;
  children?: ReactNode;
}

function StepCard({ index, title, done, description, action, children }: StepCardProps) {
  return (
    <Box
      sx={{
        p: 1.25,
        borderRadius: 1.5,
        border: '1px solid',
        borderColor: done ? 'success.main' : 'divider',
        bgcolor: 'action.hover',
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Box
          sx={{
            width: 18,
            height: 18,
            borderRadius: '50%',
            bgcolor: done ? 'success.main' : 'action.selected',
            color: done ? 'success.contrastText' : 'primary.main',
            display: 'grid',
            placeItems: 'center',
            fontSize: 9.5,
            fontWeight: 700,
            flexShrink: 0,
          }}
        >
          {done ? <CheckCircle sx={{ fontSize: 13 }} /> : index}
        </Box>
        <Typography sx={{ fontSize: 11.5, fontWeight: 700, flex: 1 }}>{title}</Typography>
        {action}
      </Box>
      <Typography component="div" sx={{ fontSize: 10.5, color: 'text.secondary', mt: 0.6, ml: 3.25 }}>
        {description}
      </Typography>
      {children ? <Box sx={{ ml: 3.25 }}>{children}</Box> : null}
    </Box>
  );
}

function messageOf(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  return '操作失败';
}
