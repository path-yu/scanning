import { useRef } from 'react';
import { Box, Tooltip, Typography } from '@mui/material';
import { PushPin, SearchOff } from '@mui/icons-material';
import { useVirtualizer } from '@tanstack/react-virtual';
import {
  formatBytes,
  formatDuration,
  mimeLabel,
  methodColor,
  shortenPath,
  statusColor,
  statusText,
} from '@/lib/format';
import type { FlowSummary } from '@/types';

interface FlowTableProps {
  flows: FlowSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  emptyTitle?: string;
  emptyHint?: string;
}

const GRID = '54px 62px 64px 84px minmax(130px, 1.05fr) minmax(200px, 1.7fr) 66px 66px 58px';
const ROW_HEIGHT = 34;

export function FlowTable({ flows, selectedId, onSelect, emptyTitle, emptyHint }: FlowTableProps) {
  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: flows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 14,
  });

  return (
    <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
      <Box
        sx={{
          height: 32,
          px: 1.5,
          display: 'grid',
          gridTemplateColumns: GRID,
          alignItems: 'center',
          columnGap: 1,
          borderBottom: '1px solid',
          borderColor: 'divider',
          flexShrink: 0,
          fontSize: 10,
          fontWeight: 700,
          letterSpacing: '0.04em',
          color: 'text.disabled',
          whiteSpace: 'nowrap',
        }}
      >
        <span>#</span>
        <span>方法</span>
        <span>状态</span>
        <span>进程</span>
        <span>域名</span>
        <span>路径</span>
        <span style={{ textAlign: 'right' }}>大小</span>
        <span style={{ textAlign: 'right' }}>耗时</span>
        <span style={{ textAlign: 'right' }}>类型</span>
      </Box>

      <Box
        ref={parentRef}
        sx={{
          flex: 1,
          minHeight: 0,
          overflow: 'auto',
          position: 'relative',
          bgcolor: 'background.default',
        }}
        role="grid"
        aria-rowcount={flows.length}
      >
        {flows.length === 0 ? (
          <Box
            sx={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 1,
              color: 'text.disabled',
            }}
          >
            <SearchOff sx={{ fontSize: 34, opacity: 0.55 }} />
            <Typography sx={{ fontSize: 12.5 }}>{emptyTitle ?? '没有匹配的流量'}</Typography>
            <Typography sx={{ fontSize: 11, opacity: 0.75, textAlign: 'center', px: 2 }}>
              {emptyHint ?? '试试清空过滤条件'}
            </Typography>
          </Box>
        ) : (
          <Box sx={{ height: virtualizer.getTotalSize(), position: 'relative', minWidth: 850 }}>
            {virtualizer.getVirtualItems().map((virtualRow) => {
              const flow = flows[virtualRow.index];
              if (!flow) return null;
              const selected = flow.id === selectedId;
              const color = statusColor(flow.statusCode);
              const method = methodColor(flow.method);
              const processLabel = flow.client.app || (flow.client.pid ? `PID ${flow.client.pid}` : '—');

              return (
                <Box
                  key={flow.id}
                  role="row"
                  aria-selected={selected}
                  onClick={() => onSelect(flow.id)}
                  sx={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    height: ROW_HEIGHT,
                    display: 'grid',
                    gridTemplateColumns: GRID,
                    columnGap: 1,
                    alignItems: 'center',
                    px: 1.5,
                    cursor: 'pointer',
                    borderBottom: '1px solid',
                    borderColor: 'divider',
                    bgcolor: selected
                      ? 'action.selected'
                      : virtualRow.index % 2 === 0
                        ? 'transparent'
                        : 'action.hover',
                    boxShadow: selected ? 'inset 2px 0 0 #38bdf8' : 'none',
                    transform: `translateY(${virtualRow.start}px)`,
                    '&:hover': { bgcolor: selected ? 'action.selected' : 'action.hover' },
                  }}
                >
                  <Box
                    component="span"
                    className="mono"
                    sx={{ fontSize: 10, color: 'text.disabled', display: 'flex', alignItems: 'center', gap: 0.4 }}
                  >
                    {flow.pinned ? <PushPin sx={{ fontSize: 10, color: 'warning.main' }} /> : null}
                    {String(flow.seq).padStart(4, '0')}
                  </Box>

                  <Box component="span" sx={{ fontSize: 10, fontWeight: 800, color: method, letterSpacing: '0.02em' }}>
                    {flow.method}
                  </Box>

                  <Tooltip title={`${flow.statusCode} ${statusText(flow.statusCode)}`}>
                    <Box
                      component="span"
                      className="mono"
                      sx={{
                        fontSize: 10.5,
                        fontWeight: 700,
                        color,
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 0.5,
                      }}
                    >
                      <Box sx={{ width: 5, height: 5, borderRadius: '50%', bgcolor: color, flexShrink: 0 }} />
                      {flow.statusCode || '···'}
                    </Box>
                  </Tooltip>

                  <Tooltip
                    title={
                      flow.client.app || flow.client.pid
                        ? `${flow.client.app || '未知进程'}${flow.client.pid ? ` · PID ${flow.client.pid}` : ''}${flow.client.appPath ? `\n${flow.client.appPath}` : ''}`
                        : '未识别到所属进程'
                    }
                  >
                    <Box
                      component="span"
                      sx={{
                        fontSize: 10,
                        color: flow.client.app ? 'text.secondary' : 'text.disabled',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {processLabel}
                    </Box>
                  </Tooltip>

                  <Tooltip title={flow.host}>
                    <Box
                      component="span"
                      sx={{
                        fontSize: 11,
                        color: 'text.primary',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {flow.host}
                    </Box>
                  </Tooltip>

                  <Tooltip title={`${flow.scheme}://${flow.host}${flow.path}`}>
                    <Box
                      component="span"
                      className="mono"
                      sx={{
                        fontSize: 10.5,
                        color: 'text.secondary',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {shortenPath(flow.path, 180)}
                    </Box>
                  </Tooltip>

                  <Box component="span" className="mono" sx={{ fontSize: 10, color: 'text.secondary', textAlign: 'right' }}>
                    {formatBytes(flow.respSize)}
                  </Box>

                  <Box
                    component="span"
                    className="mono"
                    sx={{
                      fontSize: 10,
                      textAlign: 'right',
                      color: flow.durationMs > 500 ? 'warning.main' : 'text.secondary',
                    }}
                  >
                    {formatDuration(flow.durationMs)}
                  </Box>

                  <Box
                    component="span"
                    sx={{ fontSize: 9.5, color: 'text.disabled', textAlign: 'right', fontWeight: 600 }}
                  >
                    {mimeLabel(flow.mime)}
                  </Box>
                </Box>
              );
            })}
          </Box>
        )}
      </Box>
    </Box>
  );
}
