import { useEffect, useMemo, useState } from 'react';
import { Box, Button, Chip, IconButton, InputBase, Tooltip, Typography } from '@mui/material';
import {
  Apps,
  Close,
  DataObject,
  DnsOutlined,
  LanOutlined,
  LockOutlined,
  Search,
  SwapVert,
} from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import { PacketTable } from '@/components/PacketTable';
import { PacketDetail } from '@/components/PacketDetail';
import { formatNumber } from '@/lib/format';
import type { CaptureStatus, DNSEntry, PacketSummary } from '@/types';

interface PacketViewProps {
  captureStatus?: CaptureStatus;
  onOpenCapture: () => void;
  onOpenFlow: (flowId: string) => void;
}

interface QuickFilter {
  label: string;
  value: string;
  count: number;
  icon: React.ReactNode;
  color: string;
}

export function PacketView({ captureStatus, onOpenCapture, onOpenFlow }: PacketViewProps) {
  const [protocol, setProtocol] = useState('ALL');
  const [search, setSearch] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const packetsQuery = useQuery({
    queryKey: ['packets', 'latest'],
    queryFn: () => api.listPackets({ limit: 1000, order: 'desc' }),
    refetchInterval: 1500,
  });

  const dnsQuery = useQuery({
    queryKey: ['dns'],
    queryFn: () => api.listDNS(50),
    refetchInterval: 5000,
  });

  const packets = useMemo(() => packetsQuery.data?.packets ?? [], [packetsQuery.data]);

  const counts = useMemo(() => {
    const result = { all: packets.length, tcp: 0, udp: 0, dns: 0, tls: 0, icmp: 0 };
    for (const packet of packets) {
      if (packet.kind === 'dns') result.dns += 1;
      else if (packet.kind === 'tls') result.tls += 1;
      else if (packet.kind === 'tcp') result.tcp += 1;
      else if (packet.kind === 'udp') result.udp += 1;
      else if (packet.kind === 'icmp') result.icmp += 1;
    }
    return result;
  }, [packets]);

  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return packets.filter((packet) => {
      if (protocol !== 'ALL') {
        if (protocol === 'DNS' && packet.kind !== 'dns') return false;
        if (protocol === 'TLS' && packet.kind !== 'tls') return false;
        if (protocol === 'TCP' && packet.kind !== 'tcp') return false;
        if (protocol === 'UDP' && packet.kind !== 'udp') return false;
        if (protocol === 'ICMP' && packet.kind !== 'icmp') return false;
      }
      if (!needle) return true;
      return matchesPacket(packet, needle);
    });
  }, [packets, protocol, search]);

  useEffect(() => {
    if (selectedId && !packets.some((packet) => packet.id === selectedId)) {
      setSelectedId(null);
    }
  }, [packets, selectedId]);

  const filters: QuickFilter[] = [
    { label: '全部报文', value: 'ALL', count: counts.all, icon: <Apps sx={{ fontSize: 15 }} />, color: '#94a3b8' },
    { label: 'TCP', value: 'TCP', count: counts.tcp, icon: <SwapVert sx={{ fontSize: 15 }} />, color: '#38bdf8' },
    { label: 'UDP', value: 'UDP', count: counts.udp, icon: <LanOutlined sx={{ fontSize: 15 }} />, color: '#fbbf24' },
    { label: 'DNS', value: 'DNS', count: counts.dns, icon: <DnsOutlined sx={{ fontSize: 15 }} />, color: '#a78bfa' },
    { label: 'TLS', value: 'TLS', count: counts.tls, icon: <LockOutlined sx={{ fontSize: 15 }} />, color: '#34d399' },
    { label: 'ICMP', value: 'ICMP', count: counts.icmp, icon: <DataObject sx={{ fontSize: 15 }} />, color: '#f97316' },
  ];

  const running = captureStatus?.running ?? false;
  const mirror = captureStatus?.mirror ?? false;
  const available = captureStatus?.available ?? false;
  const statusLabel = running ? '网卡采集中' : mirror ? '代理镜像' : available ? '网卡已就绪' : '网卡不可用';
  const statusColor = running ? '#34d399' : mirror ? '#a78bfa' : available ? '#38bdf8' : '#94a3b8';

  return (
    <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ flex: 1, minHeight: 0, display: 'flex' }}>
        <Box
          component="aside"
          sx={{
            width: 224,
            flexShrink: 0,
            display: 'flex',
            flexDirection: 'column',
            borderRight: '1px solid',
            borderColor: 'divider',
            bgcolor: 'background.paper',
            minHeight: 0,
          }}
        >
          <Box sx={{ px: 1.5, pt: 1.5, pb: 1 }}>
            <Box
              sx={{
                p: 1.1,
                borderRadius: 1.25,
                border: '1px solid',
                borderColor: 'divider',
                bgcolor: 'action.hover',
                cursor: 'pointer',
                '&:hover': { borderColor: 'primary.main' },
              }}
              onClick={onOpenCapture}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                <Box sx={{ width: 6, height: 6, borderRadius: '50%', bgcolor: statusColor, flexShrink: 0 }} />
                <Typography sx={{ fontSize: 11.5, fontWeight: 650 }}>{statusLabel}</Typography>
                <Box sx={{ flex: 1 }} />
                <Typography className="mono" sx={{ fontSize: 9.5, color: 'text.disabled' }}>
                  {captureStatus?.backend ?? '—'}
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 0.75 }}>
                <Typography className="mono" sx={{ fontSize: 9.5, color: 'text.disabled' }}>
                  {formatNumber(captureStatus?.packets ?? 0)} 包
                </Typography>
                <Typography className="mono" sx={{ fontSize: 9.5, color: 'text.disabled' }}>
                  {Math.round(captureStatus?.rate ?? 0)} pkt/s
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 0.25 }}>
                <Typography className="mono" sx={{ fontSize: 9.5, color: 'text.disabled' }}>
                  {formatNumber(captureStatus?.flows ?? 0)} 条 HTTP
                </Typography>
                <Typography className="mono" sx={{ fontSize: 9.5, color: 'text.disabled' }}>
                  {formatNumber(captureStatus?.dns ?? 0)} DNS
                </Typography>
              </Box>
            </Box>
          </Box>

          <Typography sx={{ px: 1.5, pt: 0.5, pb: 0.75, fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: 'text.disabled' }}>
            快速筛选
          </Typography>
          <Box sx={{ px: 0.75, display: 'flex', flexDirection: 'column', gap: 0.25 }}>
            {filters.map((item) => {
              const active = protocol === item.value;
              return (
                <Box
                  key={item.label}
                  role="button"
                  tabIndex={0}
                  onClick={() => setProtocol(item.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      setProtocol(item.value);
                    }
                  }}
                  sx={{
                    height: 29,
                    px: 1,
                    borderRadius: 1,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 0.9,
                    cursor: 'pointer',
                    color: active ? 'text.primary' : 'text.secondary',
                    bgcolor: active ? 'action.selected' : 'transparent',
                    boxShadow: active ? 'inset 2px 0 0 #38bdf8' : 'none',
                    '&:hover': { bgcolor: 'action.hover' },
                    outline: 'none',
                  }}
                >
                  <Box sx={{ display: 'flex', color: item.color, flexShrink: 0 }}>{item.icon}</Box>
                  <Typography sx={{ fontSize: 11.5, flex: 1, fontWeight: active ? 600 : 500 }}>{item.label}</Typography>
                  <Box component="span" className="mono" sx={{ fontSize: 9.5, color: 'text.disabled', bgcolor: 'action.hover', borderRadius: 0.75, px: 0.6 }}>
                    {item.count}
                  </Box>
                </Box>
              );
            })}
          </Box>

          <Typography sx={{ px: 1.5, pt: 1.5, pb: 0.75, fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: 'text.disabled' }}>
            DNS 映射
          </Typography>
          <Box sx={{ flex: 1, minHeight: 0, overflow: 'auto', px: 0.75, pb: 1 }}>
            {(dnsQuery.data ?? []).length === 0 ? (
              <Typography sx={{ px: 1, py: 1, fontSize: 10.5, color: 'text.disabled' }}>暂无 DNS 记录</Typography>
            ) : (
              (dnsQuery.data ?? []).slice(0, 20).map((entry: DNSEntry) => (
                <Tooltip key={`${entry.domain}-${entry.ip}`} placement="right" title={`${entry.ip} · TTL ${entry.ttl}s`}>
                  <Box
                    role="button"
                    tabIndex={0}
                    onClick={() => setSearch(entry.domain)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter') setSearch(entry.domain);
                    }}
                    sx={{ px: 1, py: 0.5, borderRadius: 1, cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
                  >
                    <Typography sx={{ fontSize: 10.5, color: 'text.secondary', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {entry.domain}
                    </Typography>
                    <Typography className="mono" sx={{ fontSize: 9, color: 'text.disabled' }}>
                      {entry.ip}
                    </Typography>
                  </Box>
                </Tooltip>
              ))
            )}
          </Box>

          <Box sx={{ p: 1.25, borderTop: '1px solid', borderColor: 'divider', flexShrink: 0 }}>
            <Button size="small" variant="outlined" fullWidth onClick={onOpenCapture}>
              采集与导入
            </Button>
          </Box>
        </Box>

        <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
          <Box
            sx={{
              height: 44,
              px: 1.5,
              display: 'flex',
              alignItems: 'center',
              gap: 1,
              borderBottom: '1px solid',
              borderColor: 'divider',
              flexShrink: 0,
            }}
          >
            <Box
              sx={{
                flex: 1,
                minWidth: 0,
                height: 30,
                px: 1,
                display: 'flex',
                alignItems: 'center',
                gap: 0.75,
                borderRadius: 1,
                border: '1px solid',
                borderColor: 'divider',
                bgcolor: 'action.hover',
              }}
            >
              <Search sx={{ fontSize: 15, color: 'text.disabled', flexShrink: 0 }} />
              <InputBase
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="搜索 IP、端口、域名或报文摘要"
                sx={{ flex: 1, minWidth: 0, fontSize: 12, '& input': { py: 0.4, px: 0 } }}
                inputProps={{ 'aria-label': '搜索报文' }}
              />
              {search ? (
                <IconButton size="small" onClick={() => setSearch('')} aria-label="清空搜索">
                  <Close sx={{ fontSize: 14 }} />
                </IconButton>
              ) : null}
            </Box>
            <Typography sx={{ fontSize: 10.5, color: 'text.secondary', whiteSpace: 'nowrap' }}>
              匹配{' '}
              <Box component="span" className="mono" sx={{ color: 'text.primary', fontWeight: 600 }}>
                {formatNumber(visible.length)}
              </Box>
              <Box component="span" sx={{ color: 'text.disabled' }}> / {formatNumber(packets.length)}</Box>
            </Typography>
            <Chip size="small" label={running ? '实时' : mirror ? '镜像' : '空闲'} color={running ? 'success' : mirror ? 'secondary' : 'default'} variant="outlined" />
          </Box>

          <Box sx={{ flex: 1, minHeight: 0, display: 'flex' }}>
            <PacketTable packets={visible} selectedId={selectedId} onSelect={setSelectedId} />
            {selectedId ? (
              <PacketDetail packetId={selectedId} onClose={() => setSelectedId(null)} onOpenFlow={onOpenFlow} />
            ) : null}
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

function matchesPacket(packet: PacketSummary, needle: string): boolean {
  if (packet.srcIp.includes(needle) || packet.dstIp.includes(needle)) return true;
  if (packet.host && packet.host.toLowerCase().includes(needle)) return true;
  if (packet.summary.toLowerCase().includes(needle)) return true;
  if (String(packet.srcPort) === needle || String(packet.dstPort) === needle) return true;
  return false;
}
