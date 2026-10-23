import { useMemo, useState } from 'react';
import { Box, Button, Chip, CircularProgress, IconButton, Snackbar, Tooltip, Typography } from '@mui/material';
import { Close, ContentCopy, OpenInNew } from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import { base64ToBytes, hexDump } from '@/lib/hex';
import { formatBytes, formatDateTime, formatNumber, formatTime } from '@/lib/format';
import type { ReactNode } from 'react';

interface PacketDetailProps {
  packetId: string;
  onClose: () => void;
  onOpenFlow: (flowId: string) => void;
}

function protocolColor(protocol: string): string {
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
      return '#a78bfa';
  }
}

export function PacketDetail({ packetId, onClose, onOpenFlow }: PacketDetailProps) {
  const [snack, setSnack] = useState<string | null>(null);
  const query = useQuery({
    queryKey: ['packet', packetId],
    queryFn: () => api.getPacket(packetId),
    enabled: Boolean(packetId),
  });

  const packet = query.data;
  const hex = useMemo(() => hexDump(base64ToBytes(packet?.payload)), [packet?.payload]);

  const copy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setSnack(label);
    } catch {
      setSnack('复制失败');
    }
  };

  return (
    <Box
      component="aside"
      sx={{
        width: 430,
        minWidth: 360,
        maxWidth: 520,
        flexShrink: 0,
        borderLeft: '1px solid',
        borderColor: 'divider',
        bgcolor: 'background.paper',
        display: { xs: 'none', md: 'flex' },
        flexDirection: 'column',
        minHeight: 0,
      }}
    >
      <Box sx={{ px: 1.5, pt: 1.25, pb: 1, borderBottom: '1px solid', borderColor: 'divider', flexShrink: 0 }}>
        {query.isLoading ? (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CircularProgress size={14} />
            <Typography sx={{ fontSize: 11, color: 'text.secondary' }}>加载报文…</Typography>
          </Box>
        ) : packet ? (
          <>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.9, minWidth: 0 }}>
              <Typography sx={{ fontSize: 10.5, fontWeight: 800, color: protocolColor(packet.protocol), letterSpacing: '0.03em' }}>
                {packet.protocol}
              </Typography>
              <Typography className="mono" sx={{ fontSize: 10, color: 'text.disabled' }}>
                #{formatNumber(packet.no)} · {formatTime(packet.timestamp)}
              </Typography>
              <Box sx={{ flex: 1 }} />
              <Tooltip title="复制摘要">
                <IconButton size="small" onClick={() => void copy(packet.summary, '摘要已复制')}>
                  <ContentCopy sx={{ fontSize: 14 }} />
                </IconButton>
              </Tooltip>
              <IconButton size="small" onClick={onClose} aria-label="关闭报文详情">
                <Close sx={{ fontSize: 15 }} />
              </IconButton>
            </Box>
            <Typography className="mono" sx={{ mt: 0.6, fontSize: 10.5, color: 'text.secondary', wordBreak: 'break-all' }}>
              {packet.summary}
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.75 }}>
              <Chip size="small" label={`${formatBytes(packet.captureLen)}`} variant="outlined" />
              {packet.host ? <Chip size="small" label={packet.host} color="info" variant="outlined" /> : null}
              {packet.kind === 'dns' ? <Chip size="small" label="DNS" color="secondary" variant="outlined" /> : null}
              {packet.kind === 'tls' ? <Chip size="small" label="TLS" color="success" variant="outlined" /> : null}
            </Box>
          </>
        ) : (
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Typography sx={{ fontSize: 12, color: 'text.secondary' }}>报文不存在或已被淘汰</Typography>
            <IconButton size="small" onClick={onClose}>
              <Close sx={{ fontSize: 15 }} />
            </IconButton>
          </Box>
        )}
      </Box>

      {packet ? (
        <>
          <Box sx={{ flex: 1, minHeight: 0, overflow: 'auto', p: 1.5, display: 'flex', flexDirection: 'column', gap: 1.5 }}>
            <Section title="基本信息">
              <InfoRow label="源" value={`${packet.srcIp}:${packet.srcPort}`} mono />
              <InfoRow label="目的" value={`${packet.dstIp}:${packet.dstPort}`} mono />
              <InfoRow label="捕获/原始" value={`${formatBytes(packet.captureLen)} / ${formatBytes(packet.origLen)}`} mono />
              <InfoRow label="时间" value={formatDateTime(packet.timestamp)} mono />
              {packet.host ? <InfoRow label="主机" value={packet.host} mono /> : null}
            </Section>

            {packet.tcp ? (
              <Section title="TCP">
                <InfoRow label="标志位" value={packet.tcp.flags} mono />
                <InfoRow label="Seq / Ack" value={`${packet.tcp.seq} / ${packet.tcp.ack}`} mono />
                <InfoRow label="窗口" value={formatNumber(packet.tcp.window)} mono />
                {packet.tcp.mss ? <InfoRow label="MSS" value={formatNumber(packet.tcp.mss)} mono /> : null}
              </Section>
            ) : null}

            {packet.dns ? (
              <Section title="DNS">
                <InfoRow label="方向" value={packet.dns.qr === 'response' ? '响应' : '查询'} />
                <InfoRow label="问题" value={`${packet.dns.question || '—'} ${packet.dns.qtype || ''}`} mono />
                <InfoRow label="响应码" value={packet.dns.rcode || '—'} mono />
                <InfoRow label="应答" value={(packet.dns.answers ?? []).join(', ') || '—'} mono />
                {packet.dns.cnames?.length ? <InfoRow label="CNAME" value={packet.dns.cnames.join(', ')} mono /> : null}
                {packet.dns.ttl ? <InfoRow label="TTL" value={`${packet.dns.ttl}s`} mono /> : null}
              </Section>
            ) : null}

            {packet.tls ? (
              <Section title="TLS">
                <InfoRow label="记录" value={packet.tls.recordType} mono />
                <InfoRow label="版本" value={packet.tls.version} mono />
                <InfoRow label="SNI" value={packet.tls.sni || '—'} mono />
                <InfoRow label="ALPN" value={(packet.tls.alpn ?? []).join(', ') || '—'} mono />
              </Section>
            ) : null}

            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.75 }}>
                <Typography sx={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: 'text.disabled', textTransform: 'uppercase' }}>
                  载荷
                </Typography>
                <Typography className="mono" sx={{ fontSize: 10, color: 'text.disabled' }}>
                  {base64ToBytes(packet.payload).length} B
                </Typography>
                <Box sx={{ flex: 1 }} />
                <Tooltip title="复制十六进制">
                  <span>
                    <IconButton size="small" disabled={!hex} onClick={() => void copy(hex, '十六进制已复制')}>
                      <ContentCopy sx={{ fontSize: 14 }} />
                    </IconButton>
                  </span>
                </Tooltip>
              </Box>
              {hex ? (
                <Box
                  component="pre"
                  className="mono"
                  sx={{
                    m: 0,
                    p: 1,
                    maxHeight: 300,
                    overflow: 'auto',
                    fontSize: 10,
                    lineHeight: 1.6,
                    bgcolor: 'action.hover',
                    border: '1px solid',
                    borderColor: 'divider',
                    borderRadius: 1,
                    color: 'text.secondary',
                    whiteSpace: 'pre',
                  }}
                >
                  {hex}
                </Box>
              ) : (
                <Box sx={{ border: '1px dashed', borderColor: 'divider', borderRadius: 1, p: 1.25, fontSize: 11, color: 'text.disabled' }}>
                  没有载荷预览
                </Box>
              )}
            </Box>
          </Box>

          <Box sx={{ px: 1.5, py: 1, borderTop: '1px solid', borderColor: 'divider', display: 'flex', alignItems: 'center', gap: 1, flexShrink: 0 }}>
            {packet.flowId ? (
              <Button
                size="small"
                variant="contained"
                startIcon={<OpenInNew sx={{ fontSize: 14 }} />}
                onClick={() => onOpenFlow(packet.flowId as string)}
              >
                查看关联 Flow
              </Button>
            ) : (
              <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>未关联 HTTP Flow</Typography>
            )}
            <Box sx={{ flex: 1 }} />
            <Typography className="mono" sx={{ fontSize: 10, color: 'text.disabled' }}>
              {packet.id.slice(-8)}
            </Typography>
          </Box>
        </>
      ) : null}

      <Snackbar
        open={Boolean(snack)}
        autoHideDuration={1600}
        onClose={() => setSnack(null)}
        message={snack}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      />
    </Box>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: 'text.disabled', textTransform: 'uppercase', mb: 0.75 }}>
        {title}
      </Typography>
      <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, overflow: 'hidden' }}>{children}</Box>
    </Box>
  );
}

function InfoRow({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: '82px 1fr',
        gap: 1,
        px: 1,
        py: 0.65,
        '& + &': { borderTop: '1px solid', borderTopColor: 'divider' },
      }}
    >
      <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>{label}</Typography>
      <Box className={mono ? 'mono' : undefined} sx={{ fontSize: 10.5, color: 'text.secondary', wordBreak: 'break-all', minWidth: 0 }}>
        {value}
      </Box>
    </Box>
  );
}
