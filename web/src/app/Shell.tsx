import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Box, Button, CircularProgress, type PaletteMode } from '@mui/material';
import { TopBar } from '@/components/TopBar';
import { Sidebar } from '@/components/Sidebar';
import { FilterBar } from '@/components/FilterBar';
import { FlowTable } from '@/components/FlowTable';
import { DetailPanel } from '@/components/DetailPanel';
import { StatusBar } from '@/components/StatusBar';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { OnboardingDialog } from '@/components/OnboardingDialog';
import { api } from '@/api';
import { compileFilter, plainKeyword, type SearchScope } from '@/lib/filter';
import { useFlowStore } from '@/store/flowStore';
import type { CaptureStatus, FlowSummary, ProxyStatus, SystemInfo } from '@/types';
import type { ConnectionStatus } from '@/ws';
import type { MainView } from '@/components/TopBar';

const PacketView = lazy(() => import('@/components/PacketView').then((module) => ({ default: module.PacketView })));
const CaptureDialog = lazy(() => import('@/components/CaptureDialog').then((module) => ({ default: module.CaptureDialog })));
const ProxyDialog = lazy(() => import('@/components/ProxyDialog').then((module) => ({ default: module.ProxyDialog })));
const RulesDialog = lazy(() => import('@/components/RulesDialog').then((module) => ({ default: module.RulesDialog })));
const SessionDialog = lazy(() => import('@/components/SessionDialog').then((module) => ({ default: module.SessionDialog })));
const BreakpointDialog = lazy(() =>
  import('@/components/BreakpointDialog').then((module) => ({ default: module.BreakpointDialog })),
);
const AppLauncherDialog = lazy(() =>
  import('@/components/AppLauncherDialog').then((module) => ({ default: module.AppLauncherDialog })),
);

const ONBOARDING_KEY = 'scanning.onboarding.v1';

interface ShellProps {
  info?: SystemInfo;
  infoLoading: boolean;
  proxyStatus?: ProxyStatus;
  captureStatus?: CaptureStatus;
  wsStatus: ConnectionStatus;
  themeMode: PaletteMode;
  onToggleTheme: () => void;
  onDemo: () => Promise<void>;
  demoBusy: boolean;
  onClear: () => Promise<void>;
  onDeleteFlows: (ids: string[]) => Promise<void>;
  onRefresh: () => Promise<void>;
  refreshing: boolean;
  onExportHar: () => Promise<void>;
  exporting: boolean;
  onProxyChanged: () => void;
  onCaptureChanged: () => void;
  error?: string | null;
  onDismissError: () => void;
}

export function Shell({
  info,
  infoLoading,
  proxyStatus,
  captureStatus,
  wsStatus,
  themeMode,
  onToggleTheme,
  onDemo,
  demoBusy,
  onClear,
  onDeleteFlows,
  onRefresh,
  refreshing,
  onExportHar,
  exporting,
  onProxyChanged,
  onCaptureChanged,
  error,
  onDismissError,
}: ShellProps) {
  const byId = useFlowStore((state) => state.byId);
  const order = useFlowStore((state) => state.order);
  const selectedId = useFlowStore((state) => state.selectedId);
  const select = useFlowStore((state) => state.select);
  const filter = useFlowStore((state) => state.filter);
  const setFilter = useFlowStore((state) => state.setFilter);
  const stats = useFlowStore((state) => state.stats);

  const filterInputRef = useRef<HTMLInputElement>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [confirmDeleteSelected, setConfirmDeleteSelected] = useState(false);
  const [checkedIds, setCheckedIds] = useState<Set<string>>(new Set());
  const [proxyOpen, setProxyOpen] = useState(false);
  const [captureOpen, setCaptureOpen] = useState(false);
  const [rulesOpen, setRulesOpen] = useState(false);
  const [sessionsOpen, setSessionsOpen] = useState(false);
  const [breakpointsOpen, setBreakpointsOpen] = useState(false);
  const [appsOpen, setAppsOpen] = useState(false);
  const [onboardingOpen, setOnboardingOpen] = useState(
    () => localStorage.getItem(ONBOARDING_KEY) !== 'done',
  );
  const [view, setView] = useState<MainView>('flows');
  const [searchScope, setSearchScope] = useState<SearchScope>('url');

  const allFlows = useMemo(
    () => order.map((id) => byId.get(id)).filter((flow): flow is FlowSummary => flow !== undefined),
    [byId, order],
  );

  useEffect(() => {
    setCheckedIds((prev) => {
      if (!prev.size) return prev;
      let changed = false;
      const next = new Set<string>();
      for (const id of prev) {
        if (byId.has(id)) next.add(id);
        else changed = true;
      }
      return changed ? next : prev;
    });
  }, [byId]);

  const compiled = useMemo(() => compileFilter(filter), [filter]);
  const keyword = useMemo(() => plainKeyword(filter), [filter]);
  const [bodySearch, setBodySearch] = useState<{
    query: string;
    ids: Set<string>;
    loading: boolean;
    error?: string;
  }>({ query: '', ids: new Set(), loading: false });

  useEffect(() => {
    if (!keyword || searchScope === 'url') {
      setBodySearch({ query: '', ids: new Set(), loading: false });
      return;
    }
    const controller = new AbortController();
    setBodySearch((prev) => ({ ...prev, loading: true, error: undefined }));
    const timer = window.setTimeout(() => {
      api
        .searchFlows(keyword, searchScope, controller.signal)
        .then((result) => {
          setBodySearch({ query: keyword, ids: new Set(result.ids), loading: false });
        })
        .catch((cause: unknown) => {
          if (controller.signal.aborted) return;
          setBodySearch({
            query: keyword,
            ids: new Set(),
            loading: false,
            error: cause instanceof Error ? cause.message : '正文搜索失败',
          });
        });
    }, 280);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [keyword, searchScope]);

  // 请求/响应模式下只展示服务端返回的正文命中 ID；URL 模式直接使用本地字段匹配。
  const activeBodyIds =
    searchScope !== 'url' && keyword !== null && bodySearch.query === keyword
      ? bodySearch.ids
      : null;
  const visibleFlows = useMemo(() => {
    if (keyword !== null && searchScope !== 'url') {
      return activeBodyIds ? allFlows.filter((flow) => activeBodyIds.has(flow.id)) : [];
    }
    return allFlows.filter((flow) => compiled.predicate(flow));
  }, [allFlows, compiled, keyword, searchScope, activeBodyIds]);

  const quickCounts = useMemo(
    () => ({
      all: allFlows.length,
      errors: allFlows.filter((flow) => flow.statusCode >= 400).length,
      json: allFlows.filter((flow) => flow.mime.includes('json')).length,
      slow: allFlows.filter((flow) => flow.durationMs > 300).length,
      https: allFlows.filter((flow) => flow.scheme === 'https').length,
    }),
    [allFlows],
  );

  const appStats = useMemo(() => {
    const map = new Map<string, { count: number; errors: number }>();
    for (const flow of allFlows) {
      const name = flow.client.app;
      if (!name) continue;
      const entry = map.get(name) ?? { count: 0, errors: 0 };
      entry.count += 1;
      if (flow.statusCode >= 400) entry.errors += 1;
      map.set(name, entry);
    }
    return [...map.entries()]
      .map(([name, value]) => ({ name, ...value }))
      .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  }, [allFlows]);

  const domains = useMemo(() => {
    const map = new Map<string, { count: number; bytes: number; errors: number }>();
    for (const flow of allFlows) {
      const entry = map.get(flow.host) ?? { count: 0, bytes: 0, errors: 0 };
      entry.count += 1;
      entry.bytes += flow.reqSize + flow.respSize;
      if (flow.statusCode >= 400) entry.errors += 1;
      map.set(flow.host, entry);
    }
    return [...map.entries()]
      .map(([host, value]) => ({ host, ...value }))
      .sort((a, b) => b.count - a.count || a.host.localeCompare(b.host));
  }, [allFlows]);

  const selected = selectedId ? byId.get(selectedId) : undefined;
  const pausedFlows = useMemo(
    () => allFlows.filter((flow) => flow.state === 'paused'),
    [allFlows],
  );

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const editing =
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.isContentEditable);

      if (editing) {
        if (event.key === 'Escape') target.blur();
        return;
      }

      if (view !== 'flows') return;

      if (event.key === '/') {
        event.preventDefault();
        filterInputRef.current?.focus();
        return;
      }
      if (event.key === 'Escape') {
        select(null);
        return;
      }
      if (event.key === 'j' || event.key === 'k') {
        if (!visibleFlows.length) return;
        event.preventDefault();
        const current = visibleFlows.findIndex((flow) => flow.id === selectedId);
        const next =
          event.key === 'j'
            ? Math.min(visibleFlows.length - 1, current < 0 ? 0 : current + 1)
            : Math.max(0, current < 0 ? 0 : current - 1);
        select(visibleFlows[next].id);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [select, selectedId, view, visibleFlows]);

  const handleQuickFilter = (value: string) => {
    setFilter(filter === value ? '' : value);
  };

  const handleDomain = (host: string) => {
    setFilter(filter === `host:${host}` ? '' : `host:${host}`);
  };

  const handleApp = (name: string) => {
    const value = `app:"${name}"`;
    setFilter(filter === value ? '' : value);
  };

  const toggleChecked = (id: string) => {
    setCheckedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleCheckedAll = (ids: string[], checked: boolean) => {
    setCheckedIds((prev) => {
      const next = new Set(prev);
      for (const id of ids) {
        if (checked) next.add(id);
        else next.delete(id);
      }
      return next;
    });
  };

  const handleConfirmClear = async () => {
    await onClear();
    setCheckedIds(new Set());
    setConfirmClear(false);
  };

  const handleConfirmDeleteSelected = async () => {
    try {
      await onDeleteFlows(Array.from(checkedIds));
      setCheckedIds(new Set());
    } catch {
      // 错误由上层统一展示，保留选中项便于重试。
    } finally {
      setConfirmDeleteSelected(false);
    }
  };

  const closeOnboarding = () => {
    setOnboardingOpen(false);
    localStorage.setItem(ONBOARDING_KEY, 'done');
  };

  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column', minWidth: 0 }}>
      <TopBar
        info={info}
        loading={infoLoading}
        proxyStatus={proxyStatus}
        captureStatus={captureStatus}
        wsStatus={wsStatus}
        themeMode={themeMode}
        view={view}
        onViewChange={setView}
        onToggleTheme={onToggleTheme}
        onDemo={() => void onDemo()}
        demoBusy={demoBusy}
        onClear={() => setConfirmClear(true)}
        onRefresh={() => void onRefresh()}
        refreshing={refreshing}
        onOpenProxy={() => setProxyOpen(true)}
        onOpenCapture={() => setCaptureOpen(true)}
        onOpenRules={() => setRulesOpen(true)}
        onOpenSessions={() => setSessionsOpen(true)}
        onOpenApps={() => setAppsOpen(true)}
        onOpenHelp={() => setOnboardingOpen(true)}
        onExportHar={() => void onExportHar()}
        exporting={exporting}
      />

      {error ? (
        <Box sx={{ px: 1.5, pt: 1 }}>
          <Alert severity="error" variant="outlined" onClose={onDismissError}>
            {error}
          </Alert>
        </Box>
      ) : null}

      {pausedFlows.length ? (
        <Box sx={{ px: 1.5, pt: 1 }}>
          <Alert
            severity="warning"
            variant="outlined"
            action={
              <Button color="inherit" size="small" onClick={() => setBreakpointsOpen(true)}>
                处理 {pausedFlows.length} 个断点
              </Button>
            }
          >
            {pausedFlows.length} 个请求在断点处等待；超时后会自动放行。
          </Alert>
        </Box>
      ) : null}

      <Box sx={{ flex: 1, minHeight: 0, display: 'flex' }}>
        {view === 'packets' ? (
          <Suspense
            fallback={
              <Box sx={{ flex: 1, display: 'grid', placeItems: 'center' }}>
                <CircularProgress size={24} />
              </Box>
            }
          >
            <PacketView
              captureStatus={captureStatus}
              onOpenCapture={() => setCaptureOpen(true)}
              onOpenFlow={(flowId) => {
                setView('flows');
                select(flowId);
              }}
            />
          </Suspense>
        ) : (
          <>
            <Sidebar
              quickCounts={quickCounts}
              domains={domains}
              apps={appStats}
              filter={filter}
              onQuickFilter={handleQuickFilter}
              onDomain={handleDomain}
              onApp={handleApp}
              onClearFilter={() => setFilter('')}
              info={info}
              stats={stats}
            />

            <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
              <FilterBar
                value={filter}
                onChange={setFilter}
                count={visibleFlows.length}
                total={allFlows.length}
                error={compiled.error}
                searching={searchScope !== 'url' && keyword !== null && bodySearch.loading}
                searchError={searchScope !== 'url' && keyword !== null ? bodySearch.error : undefined}
                inputRef={filterInputRef}
                searchScope={searchScope}
                onSearchScopeChange={setSearchScope}
                selectionCount={checkedIds.size}
                hasFlows={allFlows.length > 0}
                onDeleteSelected={() => setConfirmDeleteSelected(true)}
                onClearAll={() => setConfirmClear(true)}
              />

              <Box sx={{ flex: 1, minHeight: 0, display: 'flex' }}>
                <FlowTable
                  flows={visibleFlows}
                  selectedId={selectedId}
                  checkedIds={checkedIds}
                  onSelect={select}
                  onToggleChecked={toggleChecked}
                  onToggleAll={toggleCheckedAll}
                  emptyTitle={allFlows.length === 0 ? '还没有捕获到流量' : '没有匹配的流量'}
                  emptyHint={
                    allFlows.length === 0
                      ? '把系统或浏览器的 HTTP/HTTPS 代理指向 127.0.0.1:8899，然后访问任意网站；HTTPS 需先安装并信任 CA。'
                      : filter
                        ? '试试清空过滤条件'
                        : '调整过滤条件后再试'
                  }
                />
                {selected ? (
                  <DetailPanel flowId={selected.id} onClose={() => select(null)} onSelect={select} />
                ) : null}
              </Box>
            </Box>
          </>
        )}
      </Box>

      <StatusBar
        stats={stats}
        wsStatus={wsStatus}
        info={info}
        proxyStatus={proxyStatus}
        visible={visibleFlows.length}
      />

      <ConfirmDialog
        open={confirmClear}
        title="清空当前会话？"
        description="所有已抓取的流量与正文缓存都会被删除，且无法恢复。"
        confirmLabel="清空流量"
        onCancel={() => setConfirmClear(false)}
        onConfirm={() => void handleConfirmClear()}
      />

      <ConfirmDialog
        open={confirmDeleteSelected}
        title={`删除选中的 ${checkedIds.size} 条请求？`}
        description="选中请求及其正文缓存会被移除，且无法恢复。"
        confirmLabel="删除选中"
        onCancel={() => setConfirmDeleteSelected(false)}
        onConfirm={() => void handleConfirmDeleteSelected()}
      />

      <Suspense fallback={null}>
        {proxyOpen ? (
          <ProxyDialog
            open
            proxyStatus={proxyStatus}
            onClose={() => setProxyOpen(false)}
            onChanged={onProxyChanged}
          />
        ) : null}
      </Suspense>

      <Suspense fallback={null}>
        {captureOpen ? (
          <CaptureDialog
            open
            status={captureStatus}
            onClose={() => setCaptureOpen(false)}
            onChanged={onCaptureChanged}
          />
        ) : null}
      </Suspense>

      <Suspense fallback={null}>
        {rulesOpen ? <RulesDialog open onClose={() => setRulesOpen(false)} /> : null}
      </Suspense>

      <Suspense fallback={null}>
        {sessionsOpen ? (
          <SessionDialog
            open
            currentName={info?.session.name}
            onClose={() => setSessionsOpen(false)}
            onLoaded={onRefresh}
          />
        ) : null}
      </Suspense>

      <Suspense fallback={null}>
        {breakpointsOpen ? (
          <BreakpointDialog
            open
            pausedFlows={pausedFlows}
            onClose={() => setBreakpointsOpen(false)}
            onSelect={select}
            onResumed={() => undefined}
          />
        ) : null}
      </Suspense>

      <Suspense fallback={null}>
        {appsOpen ? <AppLauncherDialog open onClose={() => setAppsOpen(false)} /> : null}
      </Suspense>

      <OnboardingDialog
        open={onboardingOpen}
        onClose={closeOnboarding}
        onChanged={onProxyChanged}
        onOpenProxy={() => {
          closeOnboarding();
          setProxyOpen(true);
        }}
      />
    </Box>
  );
}
