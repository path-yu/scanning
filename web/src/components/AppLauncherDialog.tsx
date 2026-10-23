import { useState, type ReactNode } from 'react';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControlLabel,
  IconButton,
  List,
  ListItem,
  ListItemText,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import {
  Close,
  DesktopWindows,
  ExpandMore,
  FolderOpen,
  Memory,
  PlayArrow,
  Refresh,
} from '@mui/icons-material';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api';
import { formatDateTime } from '@/lib/format';
import type { AppDiagnosis, LaunchAppRequest, LaunchedAppStatus, RecentApp } from '@/types';

interface AppLauncherDialogProps {
  open: boolean;
  onClose: () => void;
}

type BusyAction = 'pick' | 'launch' | null;

export function AppLauncherDialog({ open, onClose }: AppLauncherDialogProps) {
  const queryClient = useQueryClient();
  const [path, setPath] = useState('');
  const [argsText, setArgsText] = useState('');
  const [cwd, setCwd] = useState('');
  const [chromiumFlags, setChromiumFlags] = useState(false);
  const [logOutput, setLogOutput] = useState(false);
  const [busy, setBusy] = useState<BusyAction>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hookName, setHookName] = useState('');
  const [hookAll, setHookAll] = useState(true);
  const [hookScan, setHookScan] = useState(false);
  const [hookBusy, setHookBusy] = useState(false);
  const [hookMessage, setHookMessage] = useState<string | null>(null);
  const [hookError, setHookError] = useState<string | null>(null);
  const [hookLog, setHookLog] = useState('');

  const appsQuery = useQuery({
    queryKey: ['apps'],
    queryFn: api.listApps,
    enabled: open,
    refetchInterval: open ? 2000 : false,
  });
  const recentQuery = useQuery({
    queryKey: ['apps', 'recent'],
    queryFn: api.listRecentApps,
    enabled: open,
  });
  const hookStatusQuery = useQuery({
    queryKey: ['hook', 'status'],
    queryFn: api.getHookStatus,
    enabled: open,
    retry: false,
    refetchInterval: open ? 5000 : false,
  });
  const hookProcessQuery = useQuery({
    queryKey: ['hook', 'processes', hookName],
    queryFn: () => api.listHookProcesses(hookName.trim()),
    enabled: open && hookScan && hookName.trim().length > 0,
    retry: false,
  });

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['apps'] });
  };

  const pickFile = async () => {
    setBusy('pick');
    setError(null);
    setMessage(null);
    try {
      const picked = await api.pickExecutable();
      if (!picked.canceled && picked.path) {
        setPath(picked.path);
      }
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const launch = async (override?: LaunchAppRequest) => {
    const payload: LaunchAppRequest =
      override ?? {
        path: path.trim(),
        args: argsText
          .split('\n')
          .map((item) => item.trim())
          .filter(Boolean),
        cwd: cwd.trim() || undefined,
        chromiumFlags,
        logOutput,
      };
    if (!payload.path) {
      setError('请先选择或填写应用路径');
      return;
    }
    setBusy('launch');
    setError(null);
    setMessage(null);
    try {
      const app = await api.launchApp(payload);
      setMessage(`已启动 ${app.name}（PID ${app.pid}），正在检测代理使用情况…`);
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const scanHookProcesses = async () => {
    if (!hookName.trim()) {
      setHookError('请先填写进程名，例如 cloudmusic.exe');
      return;
    }
    setHookError(null);
    setHookMessage(null);
    setHookScan(true);
    await queryClient.invalidateQueries({ queryKey: ['hook', 'processes'] });
  };

  const injectHook = async (pid?: number) => {
    if (!pid && !hookName.trim()) {
      setHookError('请先填写进程名，或从扫描结果中选择 PID');
      return;
    }
    setHookBusy(true);
    setHookError(null);
    setHookMessage(null);
    try {
      const result = await api.injectHook(pid ? { pid } : { name: hookName.trim(), all: hookAll });
      const succeeded = result.results.filter((item) => !item.error).length;
      const failed = result.results.length - succeeded;
      setHookMessage(`注入完成：成功 ${succeeded} 个${failed > 0 ? `，失败 ${failed} 个` : ''}`);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['hook', 'status'] }),
        queryClient.invalidateQueries({ queryKey: ['hook', 'processes'] }),
      ]);
    } catch (cause) {
      setHookError(messageOf(cause));
    } finally {
      setHookBusy(false);
    }
  };

  const loadHookLog = async () => {
    setHookBusy(true);
    setHookError(null);
    try {
      const result = await api.getHookLog(120);
      setHookLog(result.text || '（Hook 日志为空）');
    } catch (cause) {
      setHookError(messageOf(cause));
    } finally {
      setHookBusy(false);
    }
  };

  const apps = appsQuery.data ?? [];
  const recent = recentQuery.data ?? [];
  const hookStatus = hookStatusQuery.data;
  const hookProcesses = hookProcessQuery.data ?? [];
  const directApp = apps.find((app) => app.diagnosis?.status === 'direct');

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pr: 1 }}>
        <Box sx={{ flex: 1, fontSize: 15, fontWeight: 700 }}>桌面应用抓包</Box>
        <IconButton size="small" onClick={onClose} aria-label="关闭桌面应用抓包">
          <Close sx={{ fontSize: 16 }} />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ pt: 0.5, pb: 1 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
          <Alert severity="info" sx={{ py: 0.35 }}>
            应用将以子进程方式启动，并注入 HTTP(S)_PROXY=http://127.0.0.1:8899，不会修改系统代理。部分应用不读取环境变量，此时可改用网卡抓包或在应用内手动设置代理。
          </Alert>

          {error ? <Alert severity="error">{error}</Alert> : null}
          {message ? <Alert severity="success">{message}</Alert> : null}
          {directApp?.diagnosis ? (
            <Alert severity="warning">
              {directApp.name} 未检测到经 127.0.0.1:8899 的请求，检测到直连目标：
              {directApp.diagnosis.direct?.length
                ? directApp.diagnosis.direct.map((item) => `${item.address}:${item.port}`).join('、')
                : '未知'}
              。该应用可能不读取环境变量代理。
            </Alert>
          ) : null}

          <SectionTitle title="启动应用" icon={<DesktopWindows sx={{ fontSize: 14 }} />}>
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
              <TextField
                size="small"
                fullWidth
                label="应用路径"
                placeholder="C:\Program Files\Example\example.exe"
                value={path}
                onChange={(event) => setPath(event.target.value)}
              />
              <Button
                size="small"
                variant="outlined"
                startIcon={
                  busy === 'pick' ? <CircularProgress size={12} color="inherit" /> : <FolderOpen sx={{ fontSize: 15 }} />
                }
                onClick={() => void pickFile()}
                disabled={busy !== null}
                sx={{ flexShrink: 0, height: 34 }}
              >
                选择…
              </Button>
            </Box>

            <TextField
              size="small"
              fullWidth
              multiline
              minRows={2}
              maxRows={4}
              label="启动参数（每行一个，可选）"
              placeholder={'--profile\ntest'}
              value={argsText}
              onChange={(event) => setArgsText(event.target.value)}
            />

            <TextField
              size="small"
              fullWidth
              label="工作目录（可选）"
              value={cwd}
              onChange={(event) => setCwd(event.target.value)}
            />

            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
              <Tooltip title="仅适用于 Chromium/Electron 类应用；普通应用可能因未知参数退出">
                <FormControlLabel
                  control={
                    <Checkbox
                      size="small"
                      checked={chromiumFlags}
                      onChange={(event) => setChromiumFlags(event.target.checked)}
                    />
                  }
                  label={<Typography sx={{ fontSize: 11 }}>追加 --proxy-server 参数</Typography>}
                />
              </Tooltip>
              <FormControlLabel
                control={
                  <Checkbox
                    size="small"
                    checked={logOutput}
                    onChange={(event) => setLogOutput(event.target.checked)}
                  />
                }
                label={<Typography sx={{ fontSize: 11 }}>记录应用输出日志</Typography>}
              />
              <Box sx={{ flex: 1 }} />
              <Button
                size="small"
                variant="contained"
                startIcon={
                  busy === 'launch' ? <CircularProgress size={12} color="inherit" /> : <PlayArrow sx={{ fontSize: 15 }} />
                }
                onClick={() => void launch()}
                disabled={busy !== null || !path.trim()}
              >
                启动并抓包
              </Button>
            </Box>
          </SectionTitle>

          <Divider />

          <SectionTitle
            title="运行中的应用"
            icon={<DesktopWindows sx={{ fontSize: 14 }} />}
            action={
              <Tooltip title="刷新状态">
                <IconButton size="small" onClick={() => void refresh()} aria-label="刷新应用状态">
                  <Refresh sx={{ fontSize: 15 }} />
                </IconButton>
              </Tooltip>
            }
          >
            {apps.length === 0 ? (
              <Typography sx={{ fontSize: 11, color: 'text.disabled' }}>
                暂无启动记录。选择应用并启动后，这里会显示 PID、运行状态与日志路径。
              </Typography>
            ) : (
              <List dense disablePadding sx={{ maxHeight: 190, overflow: 'auto' }}>
                {apps.map((app) => (
                  <ListItem key={app.id} disableGutters sx={{ py: 0.35, alignItems: 'flex-start' }}>
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, minWidth: 0 }}>
                          <Typography sx={{ fontSize: 11.5, fontWeight: 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {app.name}
                          </Typography>
                          <StatusChip status={app.status} />
                          <Typography className="mono" sx={{ fontSize: 9.5, color: 'text.disabled' }}>
                            PID {app.pid}
                          </Typography>
                        </Box>
                      }
                      secondary={
                        <Box component="span" sx={{ display: 'block', fontSize: 9.5, color: 'text.secondary' }}>
                          <Tooltip title={app.path}>
                            <Box component="span" sx={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {app.path}
                            </Box>
                          </Tooltip>
                          <DiagnosisLine diagnosis={app.diagnosis} />
                          {app.error ? <Box component="span" sx={{ color: 'error.main' }}>{app.error}</Box> : null}
                          {app.logPath ? <Box component="span" sx={{ display: 'block', color: 'text.disabled' }}>日志：{app.logPath}</Box> : null}
                        </Box>
                      }
                    />
                    <Typography className="mono" sx={{ fontSize: 9, color: 'text.disabled', ml: 1, mt: 0.35, flexShrink: 0 }}>
                      {formatDateTime(app.startedAt)}
                    </Typography>
                  </ListItem>
                ))}
              </List>
            )}
          </SectionTitle>

          <Divider />

          <Accordion
            disableGutters
            elevation={0}
            sx={{
              border: '1px solid',
              borderColor: 'divider',
              borderRadius: 1,
              bgcolor: 'background.paper',
              '&:before': { display: 'none' },
            }}
          >
            <AccordionSummary
              expandIcon={<ExpandMore sx={{ fontSize: 16 }} />}
              sx={{ minHeight: 0, '& .MuiAccordionSummary-content': { my: 0.75, minWidth: 0 } }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, minWidth: 0, flex: 1 }}>
                <Memory sx={{ fontSize: 14, color: 'text.disabled' }} />
                <Typography sx={{ fontSize: 11.5, fontWeight: 650 }}>进程注入（实验）</Typography>
                <Typography sx={{ fontSize: 9.5, color: 'text.disabled' }}>
                  接管目标进程 80/443 直连
                </Typography>
                {hookStatus?.injected?.length ? (
                  <Chip
                    size="small"
                    label={`已注入 ${hookStatus.injected.length}`}
                    color="success"
                    variant="outlined"
                    sx={{ height: 16, fontSize: 8.5, ml: 'auto' }}
                  />
                ) : null}
              </Box>
            </AccordionSummary>
            <AccordionDetails sx={{ pt: 0, display: 'flex', flexDirection: 'column', gap: 1 }}>
              <Alert severity="warning" sx={{ py: 0.35 }}>
                仅 Windows x64。注入使用 CreateRemoteThread + IAT Hook，需与目标进程同权限，可能被安全软件拦截。仅对明确授权的应用使用。
              </Alert>

              {!hookStatus?.supported ? (
                <Alert severity="info" sx={{ py: 0.35 }}>当前平台不支持进程注入。</Alert>
              ) : !hookStatus.dllExists ? (
                <Alert severity="warning" sx={{ py: 0.35 }}>
                  未找到 Hook DLL：<Box component="span" className="mono">{hookStatus.dllPath}</Box>。请先执行 make hook。
                </Alert>
              ) : (
                <Typography sx={{ fontSize: 9.5, color: 'text.disabled', wordBreak: 'break-all' }}>
                  DLL：{hookStatus.dllPath} · 代理 {hookStatus.proxyAddr} · 端口 {hookStatus.ports.join('/')}
                </Typography>
              )}

              {hookError ? <Alert severity="error" sx={{ py: 0.35 }}>{hookError}</Alert> : null}
              {hookMessage ? <Alert severity="success" sx={{ py: 0.35 }}>{hookMessage}</Alert> : null}
              {hookProcessQuery.isError ? (
                <Alert severity="error" sx={{ py: 0.35 }}>{messageOf(hookProcessQuery.error)}</Alert>
              ) : null}

              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                <TextField
                  size="small"
                  fullWidth
                  label="进程名"
                  placeholder="例如 cloudmusic.exe"
                  value={hookName}
                  onChange={(event) => setHookName(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter') {
                      event.preventDefault();
                      void scanHookProcesses();
                    }
                  }}
                />
                <Button
                  size="small"
                  variant="outlined"
                  onClick={() => void scanHookProcesses()}
                  disabled={hookBusy}
                  sx={{ flexShrink: 0, height: 34 }}
                >
                  扫描进程
                </Button>
              </Box>

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flexWrap: 'wrap' }}>
                <FormControlLabel
                  control={
                    <Checkbox
                      size="small"
                      checked={hookAll}
                      onChange={(event) => setHookAll(event.target.checked)}
                    />
                  }
                  label={<Typography sx={{ fontSize: 11 }}>注入全部同名进程</Typography>}
                />
                <Button
                  size="small"
                  variant="contained"
                  onClick={() => void injectHook()}
                  disabled={hookBusy || !hookName.trim()}
                  sx={{ height: 28 }}
                >
                  注入
                </Button>
                <Button
                  size="small"
                  variant="text"
                  onClick={() => void loadHookLog()}
                  disabled={hookBusy}
                  sx={{ height: 28 }}
                >
                  查看 Hook 日志
                </Button>
                <Box sx={{ flex: 1 }} />
                <Typography sx={{ fontSize: 9.5, color: 'text.disabled' }}>{hookStatus?.message}</Typography>
              </Box>

              {hookProcessQuery.isFetching ? (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <CircularProgress size={12} />
                  <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>正在扫描进程…</Typography>
                </Box>
              ) : null}

              {hookProcesses.length > 0 ? (
                <List dense disablePadding sx={{ maxHeight: 180, overflow: 'auto' }}>
                  {hookProcesses.map((process) => (
                    <ListItem key={process.pid} disableGutters sx={{ py: 0.3, alignItems: 'flex-start' }}>
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, minWidth: 0 }}>
                            <Typography sx={{ fontSize: 11.5, fontWeight: 650 }}>{process.name}</Typography>
                            <Typography className="mono" sx={{ fontSize: 9.5, color: 'text.disabled' }}>
                              PID {process.pid}
                            </Typography>
                            {process.injected ? (
                              <Chip
                                size="small"
                                label="已注入"
                                color="success"
                                variant="outlined"
                                sx={{ height: 16, fontSize: 8.5 }}
                              />
                            ) : null}
                          </Box>
                        }
                        secondary={
                          <Box
                            component="span"
                            sx={{
                              display: 'block',
                              fontSize: 9.5,
                              color: process.error ? 'error.main' : 'text.secondary',
                              wordBreak: 'break-all',
                            }}
                          >
                            {process.error || process.message || process.path || ''}
                          </Box>
                        }
                      />
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={() => void injectHook(process.pid)}
                        disabled={hookBusy || process.injected}
                        sx={{ height: 24, ml: 1, flexShrink: 0 }}
                      >
                        {process.injected ? '已注入' : '注入'}
                      </Button>
                    </ListItem>
                  ))}
                </List>
              ) : hookScan && !hookProcessQuery.isFetching ? (
                <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>
                  未找到进程 {hookName.trim()}。请确认进程正在运行，并填写完整 exe 名称。
                </Typography>
              ) : (
                <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>
                  输入进程名并扫描后，可对单个进程或全部同名进程执行注入。
                </Typography>
              )}

              {hookLog ? (
                <Box
                  component="pre"
                  sx={{
                    m: 0,
                    maxHeight: 150,
                    overflow: 'auto',
                    p: 1,
                    borderRadius: 1,
                    bgcolor: 'action.hover',
                    fontSize: 9.5,
                    lineHeight: 1.5,
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                  }}
                >
                  {hookLog}
                </Box>
              ) : null}
              {hookStatus?.logPath ? (
                <Typography sx={{ fontSize: 9, color: 'text.disabled', wordBreak: 'break-all' }}>
                  日志：{hookStatus.logPath}
                </Typography>
              ) : null}
            </AccordionDetails>
          </Accordion>

          <Divider />

          <SectionTitle title="最近应用" icon={<PlayArrow sx={{ fontSize: 14 }} />}>
            {recent.length === 0 ? (
              <Typography sx={{ fontSize: 11, color: 'text.disabled' }}>暂无最近启动记录</Typography>
            ) : (
              <List dense disablePadding>
                {recent.map((item) => (
                  <RecentRow key={`${item.path}-${item.lastLaunchedAt}`} item={item} busy={busy !== null} onLaunch={() => void launch({ path: item.path, args: item.args, cwd: item.cwd })} />
                ))}
              </List>
            )}
          </SectionTitle>
        </Box>
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose}>关闭</Button>
      </DialogActions>
    </Dialog>
  );
}

function RecentRow({ item, busy, onLaunch }: { item: RecentApp; busy: boolean; onLaunch: () => void }) {
  return (
    <ListItem
      disableGutters
      sx={{ py: 0.35 }}
      secondaryAction={
        <Button size="small" variant="outlined" onClick={onLaunch} disabled={busy} sx={{ height: 24 }}>
          再次启动
        </Button>
      }
    >
      <ListItemText
        primary={item.name}
        secondary={
          <Box component="span" sx={{ display: 'block', fontSize: 9.5, color: 'text.secondary' }}>
            <Tooltip title={item.path}>
              <Box component="span" sx={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {item.path}
              </Box>
            </Tooltip>
            <Box component="span" sx={{ color: 'text.disabled' }}>{formatDateTime(item.lastLaunchedAt)}</Box>
          </Box>
        }
        primaryTypographyProps={{ sx: { fontSize: 11.5, fontWeight: 650 } }}
      />
    </ListItem>
  );
}

function DiagnosisLine({ diagnosis }: { diagnosis?: AppDiagnosis }) {
  if (!diagnosis) return null;
  const meta = {
    checking: { label: '检测中', color: 'info' as const },
    proxy: { label: '已走代理', color: 'success' as const },
    direct: { label: '未走代理', color: 'warning' as const },
    unknown: { label: '未检测到', color: 'default' as const },
  }[diagnosis.status];
  return (
    <Box component="span" sx={{ display: 'flex', alignItems: 'center', gap: 0.5, flexWrap: 'wrap', mt: 0.25 }}>
      <Chip size="small" label={meta.label} color={meta.color} variant="outlined" sx={{ height: 16, fontSize: 8.5 }} />
      <Box
        component="span"
        sx={{ fontSize: 9.5, color: diagnosis.status === 'direct' ? 'warning.main' : 'text.secondary' }}
      >
        {diagnosis.message}
      </Box>
      {diagnosis.direct?.length ? (
        <Box component="span" className="mono" sx={{ fontSize: 9, color: 'text.disabled' }}>
          {diagnosis.direct.map((item) => `${item.address}:${item.port}`).join('  ')}
        </Box>
      ) : null}
    </Box>
  );
}

function StatusChip({ status }: { status: LaunchedAppStatus }) {
  const meta = {
    running: { label: '运行中', color: 'success' as const },
    exited: { label: '已退出', color: 'default' as const },
    failed: { label: '启动失败', color: 'error' as const },
  }[status];
  return <Chip size="small" label={meta.label} color={meta.color} variant={status === 'running' ? 'filled' : 'outlined'} sx={{ height: 17, fontSize: 9 }} />;
}

function SectionTitle({ title, icon, action, children }: { title: string; icon: ReactNode; action?: ReactNode; children: ReactNode }) {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
        <Box sx={{ display: 'flex', color: 'text.disabled' }}>{icon}</Box>
        <Typography
          sx={{
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            color: 'text.disabled',
            flex: 1,
          }}
        >
          {title}
        </Typography>
        {action}
      </Box>
      {children}
    </Box>
  );
}

function messageOf(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  return '操作失败';
}
