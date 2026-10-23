import { Box, Tooltip, Typography } from '@mui/material';
import {
  Apps,
  DataObject,
  DesktopWindows,
  ErrorOutline,
  Language,
  LockOutlined,
  Timer,
} from '@mui/icons-material';
import type { ReactNode } from 'react';
import { formatBytes, formatNumber } from '@/lib/format';
import type { Stats, SystemInfo } from '@/types';

interface QuickCounts {
  all: number;
  errors: number;
  json: number;
  slow: number;
  https: number;
}

interface DomainEntry {
  host: string;
  count: number;
  bytes: number;
  errors: number;
}

interface AppEntry {
  name: string;
  count: number;
  errors: number;
}

interface SidebarProps {
  quickCounts: QuickCounts;
  domains: DomainEntry[];
  apps: AppEntry[];
  filter: string;
  onQuickFilter: (value: string) => void;
  onDomain: (host: string) => void;
  onApp: (name: string) => void;
  onClearFilter: () => void;
  info?: SystemInfo;
  stats: Stats | null;
}

interface QuickFilter {
  label: string;
  value: string;
  count: number;
  icon: ReactNode;
  color: string;
}

function SectionTitle({ children, icon }: { children: ReactNode; icon: ReactNode }) {
  return (
    <Box sx={{ px: 1.5, pt: 1.5, pb: 0.75, display: 'flex', alignItems: 'center', gap: 0.75 }}>
      <Box sx={{ display: 'flex', color: 'text.disabled' }}>{icon}</Box>
      <Typography variant="overline" sx={{ color: 'text.disabled', lineHeight: 1 }}>
        {children}
      </Typography>
    </Box>
  );
}

export function Sidebar({
  quickCounts,
  domains,
  apps,
  filter,
  onQuickFilter,
  onDomain,
  onApp,
  onClearFilter,
  info,
  stats,
}: SidebarProps) {
  const filters: QuickFilter[] = [
    { label: '全部流量', value: '', count: quickCounts.all, icon: <Apps sx={{ fontSize: 15 }} />, color: '#94a3b8' },
    { label: '错误请求', value: 'status:>=400', count: quickCounts.errors, icon: <ErrorOutline sx={{ fontSize: 15 }} />, color: '#f87171' },
    { label: 'JSON', value: 'mime:application/json', count: quickCounts.json, icon: <DataObject sx={{ fontSize: 15 }} />, color: '#38bdf8' },
    { label: '慢请求', value: 'duration:>300ms', count: quickCounts.slow, icon: <Timer sx={{ fontSize: 15 }} />, color: '#fbbf24' },
    { label: 'HTTPS', value: 'scheme:https', count: quickCounts.https, icon: <LockOutlined sx={{ fontSize: 15 }} />, color: '#34d399' },
  ];

  const maxDomainCount = domains.reduce((max, item) => Math.max(max, item.count), 1);

  return (
    <Box
      component="aside"
      sx={{
        width: 236,
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        borderRight: '1px solid',
        borderColor: 'divider',
        bgcolor: 'background.paper',
        minHeight: 0,
      }}
    >
      <SectionTitle icon={<Apps sx={{ fontSize: 13 }} />}>快速筛选</SectionTitle>
      <Box sx={{ px: 0.75, display: 'flex', flexDirection: 'column', gap: 0.25 }}>
        {filters.map((item) => {
          const active = filter === item.value;
          return (
            <Box
              key={item.label}
              role="button"
              tabIndex={0}
              onClick={() => (item.value === '' && filter !== '' ? onClearFilter() : onQuickFilter(item.value))}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  onQuickFilter(item.value);
                }
              }}
              sx={{
                height: 30,
                px: 1,
                borderRadius: 1,
                display: 'flex',
                alignItems: 'center',
                gap: 0.9,
                cursor: 'pointer',
                color: active ? 'text.primary' : 'text.secondary',
                bgcolor: active ? 'action.selected' : 'transparent',
                boxShadow: active ? 'inset 2px 0 0 #38bdf8' : 'none',
                transition: 'background-color 120ms ease',
                '&:hover': { bgcolor: 'action.hover' },
                outline: 'none',
                '&:focus-visible': { boxShadow: 'inset 0 0 0 1px #38bdf8' },
              }}
            >
              <Box sx={{ display: 'flex', color: item.color, flexShrink: 0 }}>{item.icon}</Box>
              <Typography sx={{ fontSize: 12, flex: 1, fontWeight: active ? 600 : 500 }}>
                {item.label}
              </Typography>
              <Box
                component="span"
                className="mono"
                sx={{
                  fontSize: 10,
                  color: active ? 'text.secondary' : 'text.disabled',
                  bgcolor: 'action.hover',
                  borderRadius: 0.75,
                  px: 0.6,
                  py: 0.1,
                  minWidth: 20,
                  textAlign: 'center',
                }}
              >
                {item.count}
              </Box>
            </Box>
          );
        })}
      </Box>

      <SectionTitle icon={<DesktopWindows sx={{ fontSize: 13 }} />}>进程</SectionTitle>
      <Typography sx={{ px: 1.5, pb: 0.5, fontSize: 9, color: 'text.disabled' }}>
        仅显示经代理产生流量的进程
      </Typography>
      <Box sx={{ maxHeight: 150, overflow: 'auto', px: 0.75, pb: 0.5 }}>
        {apps.length === 0 ? (
          <Typography sx={{ px: 1, py: 1, fontSize: 11, color: 'text.disabled' }}>
            暂无进程信息
          </Typography>
        ) : (
          apps.map((app) => {
            const value = `app:"${app.name}"`;
            const active = filter === value;
            return (
              <Tooltip
                key={app.name}
                placement="right"
                title={`${app.count} 条${app.errors ? ` · ${app.errors} 个错误` : ''} · 点击筛选`}
              >
                <Box
                  role="button"
                  tabIndex={0}
                  onClick={() => onApp(app.name)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      onApp(app.name);
                    }
                  }}
                  sx={{
                    height: 26,
                    px: 1,
                    borderRadius: 1,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 0.75,
                    cursor: 'pointer',
                    bgcolor: active ? 'action.selected' : 'transparent',
                    boxShadow: active ? 'inset 2px 0 0 #a78bfa' : 'none',
                    '&:hover': { bgcolor: 'action.hover' },
                    outline: 'none',
                    '&:focus-visible': { boxShadow: 'inset 0 0 0 1px #38bdf8' },
                  }}
                >
                  <Typography
                    sx={{
                      fontSize: 11,
                      color: active ? 'text.primary' : 'text.secondary',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      flex: 1,
                    }}
                  >
                    {app.name}
                  </Typography>
                  <Box
                    component="span"
                    className="mono"
                    sx={{ fontSize: 9.5, color: app.errors ? 'error.main' : 'text.disabled' }}
                  >
                    {formatNumber(app.count)}
                  </Box>
                </Box>
              </Tooltip>
            );
          })
        )}
      </Box>

      <SectionTitle icon={<Language sx={{ fontSize: 13 }} />}>域名</SectionTitle>
      <Box sx={{ flex: 1, minHeight: 0, overflow: 'auto', px: 0.75, pb: 1 }}>
        {domains.length === 0 ? (
          <Typography sx={{ px: 1, py: 1, fontSize: 11, color: 'text.disabled' }}>
            暂无流量
          </Typography>
        ) : (
          domains.map((domain) => {
            const active = filter === `host:${domain.host}`;
            return (
              <Tooltip
                key={domain.host}
                placement="right"
                title={`${domain.count} 条 · ${formatBytes(domain.bytes)}${domain.errors ? ` · ${domain.errors} 个错误` : ''}`}
              >
                <Box
                  role="button"
                  tabIndex={0}
                  onClick={() => onDomain(domain.host)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      onDomain(domain.host);
                    }
                  }}
                  sx={{
                    position: 'relative',
                    px: 1,
                    py: 0.65,
                    borderRadius: 1,
                    cursor: 'pointer',
                    overflow: 'hidden',
                    bgcolor: active ? 'action.selected' : 'transparent',
                    '&:hover': { bgcolor: 'action.hover' },
                    outline: 'none',
                    '&:focus-visible': { boxShadow: 'inset 0 0 0 1px #38bdf8' },
                  }}
                >
                  <Box
                    sx={{
                      position: 'absolute',
                      left: 0,
                      bottom: 0,
                      height: 2,
                      width: `${Math.max(6, (domain.count / maxDomainCount) * 100)}%`,
                      bgcolor: domain.errors ? 'error.main' : 'primary.main',
                      opacity: 0.35,
                    }}
                  />
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                    <Typography
                      sx={{
                        fontSize: 11.5,
                        color: active ? 'text.primary' : 'text.secondary',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        flex: 1,
                      }}
                    >
                      {domain.host}
                    </Typography>
                    <Box component="span" className="mono" sx={{ fontSize: 9.5, color: 'text.disabled' }}>
                      {formatNumber(domain.count)}
                    </Box>
                  </Box>
                </Box>
              </Tooltip>
            );
          })
        )}
      </Box>

      <Box sx={{ p: 1.25, borderTop: '1px solid', borderColor: 'divider', flexShrink: 0 }}>
        <Box
          sx={{
            p: 1.1,
            borderRadius: 1.25,
            border: '1px solid',
            borderColor: 'divider',
            bgcolor: 'action.hover',
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
            <Typography sx={{ fontSize: 10.5, fontWeight: 700, color: 'text.secondary' }}>
              本地缓存
            </Typography>
            <Box className="mono" sx={{ fontSize: 9.5, color: 'text.disabled' }}>
              {stats ? `${formatNumber(stats.flows)} / ${formatNumber(stats.capacity)}` : '—'}
            </Box>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>
              {info?.session.name ?? '默认会话'}
            </Typography>
            <Typography className="mono" sx={{ fontSize: 9.5, color: 'text.disabled' }}>
              {formatBytes(stats?.bytes ?? info?.store.bytes ?? 0)}
            </Typography>
          </Box>
        </Box>
      </Box>
    </Box>
  );
}
