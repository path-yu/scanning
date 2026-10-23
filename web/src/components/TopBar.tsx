import { type KeyboardEvent } from 'react';
import {
  Box,
  Button,
  CircularProgress,
  Divider,
  IconButton,
  Skeleton,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  type PaletteMode,
} from '@mui/material';
import {
  AutoAwesome,
  DarkMode,
  DeleteOutline,
  DesktopWindows,
  FileDownloadOutlined,
  Grain,
  HelpOutline,
  LightMode,
  ListAlt,
  Refresh,
  Rule,
  SaveOutlined,
  Settings,
  TrackChanges,
} from '@mui/icons-material';
import type { CaptureStatus, ProxyStatus, SystemInfo } from '@/types';
import type { ConnectionStatus } from '@/ws';

export type MainView = 'flows' | 'packets';

interface TopBarProps {
  info?: SystemInfo;
  loading: boolean;
  proxyStatus?: ProxyStatus;
  captureStatus?: CaptureStatus;
  wsStatus: ConnectionStatus;
  themeMode: PaletteMode;
  view: MainView;
  onViewChange: (view: MainView) => void;
  onToggleTheme: () => void;
  onDemo: () => void;
  demoBusy: boolean;
  onClear: () => void;
  onRefresh: () => void;
  refreshing: boolean;
  onOpenProxy: () => void;
  onOpenCapture: () => void;
  onOpenRules: () => void;
  onOpenSessions: () => void;
  onOpenApps: () => void;
  onOpenHelp: () => void;
  onExportHar: () => void;
  exporting: boolean;
}

const interactiveSx = {
  display: 'flex',
  cursor: 'pointer',
  borderRadius: 1,
  '&:focus-visible': {
    outline: '2px solid',
    outlineColor: 'primary.main',
    outlineOffset: 2,
  },
} as const;

function interactiveProps(handler: () => void) {
  return {
    role: 'button' as const,
    tabIndex: 0,
    onClick: handler,
    onKeyDown: (event: KeyboardEvent<HTMLDivElement>) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        handler();
      }
    },
  };
}

function StatusPill({ color, label, tooltip }: { color: string; label: string; tooltip: string }) {
  return (
    <Tooltip title={tooltip}>
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 0.75,
          height: 26,
          px: 1,
          borderRadius: 1,
          border: '1px solid',
          borderColor: 'divider',
          bgcolor: 'action.hover',
          fontSize: 11.5,
          color: 'text.secondary',
          whiteSpace: 'nowrap',
        }}
      >
        <Box sx={{ width: 6, height: 6, borderRadius: '50%', bgcolor: color, flexShrink: 0 }} />
        {label}
      </Box>
    </Tooltip>
  );
}

const wsStatusMeta: Record<ConnectionStatus, { color: string; label: string; tip: string }> = {
  open: { color: '#34d399', label: '实时', tip: 'WebSocket 实时通道已连接' },
  connecting: { color: '#fbbf24', label: '连接中', tip: '正在连接实时通道' },
  closed: { color: '#f87171', label: '离线', tip: '实时通道已断开，正在自动重连' },
};

export function TopBar({
  info,
  loading,
  proxyStatus,
  captureStatus,
  wsStatus,
  themeMode,
  view,
  onViewChange,
  onToggleTheme,
  onDemo,
  demoBusy,
  onClear,
  onRefresh,
  refreshing,
  onOpenProxy,
  onOpenCapture,
  onOpenRules,
  onOpenSessions,
  onOpenApps,
  onOpenHelp,
  onExportHar,
  exporting,
}: TopBarProps) {
  const ws = wsStatusMeta[wsStatus];
  const proxyRunning = proxyStatus?.running ?? false;
  const proxyFailed = !proxyRunning && Boolean(proxyStatus?.error);
  const proxyColor = proxyRunning ? '#34d399' : proxyFailed ? '#fbbf24' : '#f87171';
  const proxyLabel = proxyRunning ? '代理运行中' : proxyFailed ? '代理启动失败' : '代理未启动';
  const proxyTip = proxyRunning
    ? `${proxyStatus?.addr ?? '127.0.0.1:8899'} · MITM ${proxyStatus?.mitm ? '已启用' : '未启用'} · 点击管理`
    : proxyFailed
      ? proxyStatus?.error ?? '代理启动失败'
      : '点击启动 HTTP/HTTPS 代理并配置证书';

  const captureRunning = captureStatus?.running ?? false;
  const captureAvailable = captureStatus?.available ?? false;
  const captureMirror = captureStatus?.mirror ?? false;
  const captureLabel = captureRunning ? '网卡采集中' : captureMirror ? '代理镜像' : captureAvailable ? '网卡已就绪' : '网卡不可用';
  const captureColor = captureRunning ? '#34d399' : captureMirror ? '#a78bfa' : captureAvailable ? '#38bdf8' : '#94a3b8';
  const captureTip = captureRunning
    ? `${captureStatus?.interface ?? ''} · ${captureStatus?.bpf ?? ''} · ${captureStatus?.packets ?? 0} 个报文 · 点击管理`
    : captureStatus?.reason || '点击打开网卡采集、PCAP 导入或代理镜像';

  return (
    <Box
      component="header"
      sx={{
        height: 56,
        px: 1.5,
        display: 'flex',
        alignItems: 'center',
        gap: 1,
        borderBottom: '1px solid',
        borderColor: 'divider',
        bgcolor: 'background.paper',
        flexShrink: 0,
      }}
    >
      <Box
        sx={{
          width: 28,
          height: 28,
          borderRadius: '8px',
          background: 'linear-gradient(135deg, #38bdf8 0%, #6366f1 100%)',
          display: 'grid',
          placeItems: 'center',
          boxShadow: '0 0 0 1px rgba(56,189,248,0.18), 0 6px 16px rgba(56,189,248,0.16)',
          flexShrink: 0,
        }}
      >
        <TrackChanges sx={{ fontSize: 17, color: '#04121c' }} />
      </Box>

      <Box sx={{ minWidth: 0, lineHeight: 1 }}>
        <Box sx={{ fontSize: 15.5, fontWeight: 750, letterSpacing: '-0.02em' }}>Scanning</Box>
        <Box
          sx={{
            mt: 0.35,
            fontSize: 9.5,
            letterSpacing: '0.14em',
            color: 'text.disabled',
            fontWeight: 700,
            display: { xs: 'none', md: 'block' },
          }}
        >
          LOCAL TRAFFIC INSPECTOR
        </Box>
      </Box>

      <Divider orientation="vertical" flexItem sx={{ mx: 0.25, display: { xs: 'none', md: 'block' } }} />

      <ToggleButtonGroup
        exclusive
        size="small"
        value={view}
        onChange={(_, value: MainView | null) => {
          if (value) onViewChange(value);
        }}
        sx={{
          display: { xs: 'none', sm: 'flex' },
          '& .MuiToggleButton-root': {
            height: 28,
            px: 1,
            py: 0,
            gap: 0.4,
            fontSize: 11.5,
            fontWeight: 700,
            color: 'text.secondary',
            borderColor: 'divider',
            textTransform: 'none',
          },
          '& .MuiToggleButton-root.Mui-selected': {
            bgcolor: 'action.selected',
            color: 'primary.main',
          },
        }}
      >
        <ToggleButton value="flows" aria-label="流量视图">
          <ListAlt sx={{ fontSize: 14 }} />
          流量
        </ToggleButton>
        <ToggleButton value="packets" aria-label="报文视图">
          <Grain sx={{ fontSize: 14 }} />
          报文
        </ToggleButton>
      </ToggleButtonGroup>

      <Box {...interactiveProps(onOpenProxy)} aria-label="代理状态" sx={interactiveSx}>
        <StatusPill color={proxyColor} label={proxyLabel} tooltip={proxyTip} />
      </Box>
      <Box {...interactiveProps(onOpenCapture)} aria-label="网卡采集状态" sx={interactiveSx}>
        <StatusPill color={captureColor} label={captureLabel} tooltip={captureTip} />
      </Box>
      {info?.demo.enabled ? (
        <Box sx={{ display: { xs: 'none', sm: 'block' } }}>
          <StatusPill color="#a78bfa" label="演示数据" tooltip="当前流量由后端演示生成器提供" />
        </Box>
      ) : null}

      <Box sx={{ flex: 1 }} />

      <Box sx={{ display: { xs: 'none', md: 'flex' }, alignItems: 'center', gap: 0.75 }}>
        <StatusPill color={ws.color} label={ws.label} tooltip={ws.tip} />
      </Box>

      <Box
        sx={{
          display: { xs: 'none', sm: 'flex' },
          alignItems: 'center',
          height: 26,
          px: 1,
          borderRadius: 1,
          border: '1px solid',
          borderColor: 'divider',
          fontSize: 11.5,
          color: 'text.secondary',
          maxWidth: 180,
        }}
      >
        {loading ? (
          <Skeleton width={80} height={14} />
        ) : (
          <Box component="span" sx={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            会话 · {info?.session.name ?? '默认会话'}
          </Box>
        )}
      </Box>

      {info?.demo.enabled ? (
        <Tooltip title="生成 12 条演示流量">
          <span>
            <Button
              size="small"
              variant="outlined"
              color="secondary"
              startIcon={demoBusy ? <CircularProgress size={12} color="inherit" /> : <AutoAwesome sx={{ fontSize: 15 }} />}
              onClick={onDemo}
              disabled={demoBusy}
              sx={{ height: 28, display: { xs: 'none', sm: 'inline-flex' } }}
            >
              模拟流量
            </Button>
          </span>
        </Tooltip>
      ) : null}

      <Tooltip title="规则引擎（Mock / 阻断 / 断点）">
        <IconButton size="small" onClick={onOpenRules} aria-label="规则引擎">
          <Rule sx={{ fontSize: 17 }} />
        </IconButton>
      </Tooltip>

      <Tooltip title="会话存档（保存 / 加载）">
        <IconButton size="small" onClick={onOpenSessions} aria-label="会话存档">
          <SaveOutlined sx={{ fontSize: 17 }} />
        </IconButton>
      </Tooltip>

      <Tooltip title="桌面应用抓包（注入代理环境变量）">
        <IconButton size="small" onClick={onOpenApps} aria-label="桌面应用抓包">
          <DesktopWindows sx={{ fontSize: 17 }} />
        </IconButton>
      </Tooltip>

      <Tooltip title="快速开始与连通性自检">
        <IconButton size="small" onClick={onOpenHelp} aria-label="快速开始与连通性自检">
          <HelpOutline sx={{ fontSize: 17 }} />
        </IconButton>
      </Tooltip>

      <Tooltip title="导出当前过滤结果为 HAR">
        <span>
          <IconButton size="small" onClick={onExportHar} disabled={exporting} aria-label="导出 HAR">
            {exporting ? <CircularProgress size={14} /> : <FileDownloadOutlined sx={{ fontSize: 17 }} />}
          </IconButton>
        </span>
      </Tooltip>

      <Tooltip title="刷新流量列表">
        <span>
          <IconButton size="small" onClick={onRefresh} disabled={refreshing} aria-label="刷新流量">
            <Refresh sx={{ fontSize: 17 }} />
          </IconButton>
        </span>
      </Tooltip>

      <Tooltip title="清空当前会话">
        <IconButton size="small" onClick={onClear} aria-label="清空会话">
          <DeleteOutline sx={{ fontSize: 17 }} />
        </IconButton>
      </Tooltip>

      <Tooltip title={themeMode === 'dark' ? '切换到浅色主题' : '切换到深色主题'}>
        <IconButton size="small" onClick={onToggleTheme} aria-label="切换主题">
          {themeMode === 'dark' ? <LightMode sx={{ fontSize: 17 }} /> : <DarkMode sx={{ fontSize: 17 }} />}
        </IconButton>
      </Tooltip>

      <Tooltip title="设置（后续开放）">
        <span>
          <IconButton size="small" disabled>
            <Settings sx={{ fontSize: 17 }} />
          </IconButton>
        </span>
      </Tooltip>
    </Box>
  );
}
