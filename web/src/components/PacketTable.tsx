import { useRef } from 'react';
import { Box, Tooltip, Typography } from '@mui/material';
import { CallSplit, SearchOff } from '@mui/icons-material';
import { useVirtualizer } from '@tanstack/react-virtual';
import { formatNumber, formatTime } from '@/lib/format';
import type { PacketSummary } from '@/types';

interface PacketTableProps {
  packets: PacketSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

const GRID = '58px 84px 58px minmax(140px, 1fr) minmax(140px, 1fr) 58px minmax(200px, 1.8fr) 30px';
const ROW_HEIGHT = 32;

function protocolColor(protocol: string, kind?: string): string {
  if (kind === 'dns') return '#a78bfa';
  if (kind === 'tls') return '#34d399';
  switch (protocol) {
    case 'TCP':
      return '#38bdf8';
    case 'UDP':
      return '#fbbf24';
    case 'ICMP':
    case 'ICMPv6':
      return '#f97316';
    case 'ARP':
      return '#94a3b8';
    default:
      return '#8b97a6';
  }
}

function endpoint(ip: string, port: number): string {
  if (!port) return ip || '—';
  return `${ip}:${port}`;
}

export function PacketTable({ packets, selectedId, onSelect }: PacketTableProps) {
  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: packets.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 16,
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
        <span>时间</span>
        <span>协议</span>
        <span>来源</span>
        <span>目的</span>
        <span style={{ textAlign: 'right' }}>长度</span>
        <span>摘要</span>
        <span />
      </Box>

      <Box
        ref={parentRef}
        sx={{ flex: 1, minHeight: 0, overflow: 'auto', position: 'relative', bgcolor: 'background.default' }}
        role="grid"
        aria-rowcount={packets.length}
      >
        {packets.length === 0 ? (
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
              px: 3,
              textAlign: 'center',
            }}
          >
            <SearchOff sx={{ fontSize: 34, opacity: 0.55 }} />
            <Typography sx={{ fontSize: 12.5 }}>还没有报文</Typography>
            <Typography sx={{ fontSize: 11, opacity: 0.75 }}>
              打开「网卡采集」导入 PCAP、开启代理镜像，或启动实时网卡抓包
            </Typography>
          </Box>
        ) : (
          <Box sx={{ height: virtualizer.getTotalSize(), position: 'relative', minWidth: 860 }}>
            {virtualizer.getVirtualItems().map((virtualRow) => {
              const packet = packets[virtualRow.index];
              if (!packet) return null;
              const selected = packet.id === selectedId;
              const color = protocolColor(packet.protocol, packet.kind);

              return (
                <Box
                  key={packet.id}
                  role="row"
                  aria-selected={selected}
                  onClick={() => onSelect(packet.id)}
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
                    boxShadow: selected ? 'inset 2px 0 0 #a78bfa' : 'none',
                    '&:hover': { bgcolor: selected ? 'action.selected' : 'action.hover' },
                  }}
                >
                  <Box component="span" className="mono" sx={{ fontSize: 10, color: 'text.disabled' }}>
                    {formatNumber(packet.no)}
                  </Box>
                  <Box component="span" className="mono" sx={{ fontSize: 10, color: 'text.secondary' }}>
                    {formatTime(packet.timestamp)}
                  </Box>
                  <Box component="span" sx={{ fontSize: 9.5, fontWeight: 800, color, letterSpacing: '0.03em' }}>
                    {packet.protocol}
                  </Box>
                  <Tooltip title={endpoint(packet.srcIp, packet.srcPort)}>
                    <Box component="span" className="mono" sx={{ fontSize: 10, color: 'text.secondary', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {endpoint(packet.srcIp, packet.srcPort)}
                    </Box>
                  </Tooltip>
                  <Tooltip title={endpoint(packet.dstIp, packet.dstPort)}>
                    <Box component="span" className="mono" sx={{ fontSize: 10, color: 'text.secondary', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {endpoint(packet.dstIp, packet.dstPort)}
                    </Box>
                  </Tooltip>
                  <Box component="span" className="mono" sx={{ fontSize: 10, color: 'text.disabled', textAlign: 'right' }}>
                    {formatNumber(packet.captureLen)}
                  </Box>
                  <Tooltip title={packet.summary}>
                    <Box component="span" className="mono" sx={{ fontSize: 10.5, color: 'text.primary', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {packet.summary}
                    </Box>
                  </Tooltip>
                  <Box sx={{ display: 'grid', placeItems: 'center' }}>
                    {packet.flowId ? (
                      <Tooltip title="已关联 HTTP Flow">
                        <CallSplit sx={{ fontSize: 13, color: 'primary.main' }} />
                      </Tooltip>
                    ) : null}
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
