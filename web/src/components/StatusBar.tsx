import { Box, CircularProgress, Tooltip } from '@mui/material';
import { formatBytes, formatNumber } from '@/lib/format';
import type { ProxyStatus, Stats, SystemInfo } from '@/types';
import type { ConnectionStatus } from '@/ws';

interface StatusBarProps {
  stats: Stats | null;
  wsStatus: ConnectionStatus;
  info?: SystemInfo;
  proxyStatus?: ProxyStatus;
  visible: number;
}

const wsLabels: Record<ConnectionStatus, { text: string; color: string }> = {
  open: { text: '实时通道已连接', color: '#34d399' },
  connecting: { text: '正在连接实时通道', color: '#fbbf24' },
  closed: { text: '实时通道已断开，正在重连', color: '#f87171' },
};

export function StatusBar({ stats, wsStatus, info, proxyStatus, visible }: StatusBarProps) {
  const ws = wsLabels[wsStatus];
  const proxyRunning = proxyStatus?.running ?? false;
  const separator = <Box sx={{ width: 1, height: 11, bgcolor: 'divider', flexShrink: 0 }} />;

  return (
    <Box
      sx={{
        height: 30,
        px: 1.5,
        display: 'flex',
        alignItems: 'center',
        gap: 1.25,
        borderTop: '1px solid',
        borderColor: 'divider',
        bgcolor: 'background.paper',
        color: 'text.secondary',
        fontSize: 11.5,
        flexShrink: 0,
        overflow: 'hidden',
        whiteSpace: 'nowrap',
      }}
    >
      <Tooltip title={ws.text}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
          {wsStatus === 'connecting' ? (
            <CircularProgress size={8} sx={{ color: ws.color }} />
          ) : (
            <Box sx={{ width: 6, height: 6, borderRadius: '50%', bgcolor: ws.color }} />
          )}
          <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
            {wsStatus === 'open' ? '实时' : wsStatus === 'connecting' ? '连接中' : '离线'}
          </Box>
        </Box>
      </Tooltip>

      {separator}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.6 }}>
        <Box
          sx={{
            width: 5,
            height: 5,
            borderRadius: '50%',
            bgcolor: proxyRunning ? '#34d399' : 'text.disabled',
          }}
        />
        <Box component="span" sx={{ color: 'text.primary', fontWeight: 600 }}>
          {proxyRunning ? `代理 ${proxyStatus?.addr ?? ''}` : '代理未启动'}
        </Box>
      </Box>
      <Box component="span" sx={{ display: { xs: 'none', md: 'inline' } }}>
        数据不出本机
      </Box>

      {separator}
      <Box component="span">
        可见 <Box component="span" className="mono">{formatNumber(visible)}</Box>
      </Box>

      <Box sx={{ flex: 1 }} />

      <Box component="span" sx={{ display: { xs: 'none', lg: 'inline' } }}>
        总流量 <Box component="span" className="mono">{formatNumber(stats?.flows ?? info?.store.count ?? 0)}</Box>
      </Box>
      <Box component="span" sx={{ display: { xs: 'none', lg: 'inline' } }}>
        体积 <Box component="span" className="mono">{formatBytes(stats?.bytes ?? info?.store.bytes ?? 0)}</Box>
      </Box>
      <Box component="span" sx={{ display: { xs: 'none', md: 'inline' } }}>
        内存 <Box component="span" className="mono">{formatBytes(stats?.memoryBytes ?? 0)}</Box>
      </Box>
      <Box component="span" sx={{ display: { xs: 'none', lg: 'inline' } }}>
        QPS <Box component="span" className="mono">{stats?.qps ?? 0}</Box>
      </Box>

      {separator}
      <Box component="span" className="mono" sx={{ color: 'text.disabled' }}>
        v{info?.version ?? '0.1.0'}
      </Box>
    </Box>
  );
}
