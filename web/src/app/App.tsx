import { useCallback, useEffect, useMemo, useState } from 'react';
import { CssBaseline, ThemeProvider, type PaletteMode } from '@mui/material';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api';
import { createAppTheme } from '@/theme';
import { Shell } from '@/app/Shell';
import { useFlowStore } from '@/store/flowStore';
import { connectEvents, type ConnectionStatus } from '@/ws';

const THEME_KEY = 'scanning.theme';

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return '请求失败';
}

export default function App() {
  const [mode, setMode] = useState<PaletteMode>(() =>
    localStorage.getItem(THEME_KEY) === 'light' ? 'light' : 'dark',
  );
  const theme = useMemo(() => createAppTheme(mode), [mode]);
  const queryClient = useQueryClient();

  const setAll = useFlowStore((state) => state.setAll);
  const addFlows = useFlowStore((state) => state.add);
  const setStats = useFlowStore((state) => state.setStats);
  const removeAll = useFlowStore((state) => state.removeAll);

  const [wsStatus, setWsStatus] = useState<ConnectionStatus>('connecting');
  const [actionError, setActionError] = useState<string | null>(null);
  const [demoBusy, setDemoBusy] = useState(false);
  const [exporting, setExporting] = useState(false);

  const filter = useFlowStore((state) => state.filter);

  const infoQuery = useQuery({
    queryKey: ['system-info'],
    queryFn: api.getInfo,
  });

  const flowsQuery = useQuery({
    queryKey: ['flows', 'initial'],
    queryFn: () => api.listFlows({ limit: 500, order: 'asc' }),
  });

  const proxyQuery = useQuery({
    queryKey: ['proxy-status'],
    queryFn: api.getProxyStatus,
    refetchInterval: 2000,
  });

  const captureQuery = useQuery({
    queryKey: ['capture-status'],
    queryFn: api.getCaptureStatus,
    refetchInterval: 3000,
  });

  useEffect(() => {
    if (flowsQuery.data) {
      setAll(flowsQuery.data.flows);
    }
  }, [flowsQuery.data, setAll]);

  useEffect(() => {
    const close = connectEvents({
      onFlows: (flows) => addFlows(flows),
      onStats: setStats,
      onStatus: setWsStatus,
      onCleared: removeAll,
      onCaptureStatus: (status) => queryClient.setQueryData(['capture-status'], status),
    });
    return close;
  }, [addFlows, queryClient, removeAll, setStats]);

  useEffect(() => {
    localStorage.setItem(THEME_KEY, mode);
  }, [mode]);

  const handleDemo = useCallback(async () => {
    setDemoBusy(true);
    setActionError(null);
    try {
      await api.demoFlows(12);
      if (wsStatus !== 'open') {
        const data = await api.listFlows({ limit: 500, order: 'asc' });
        setAll(data.flows);
      }
    } catch (error) {
      setActionError(errorMessage(error));
    } finally {
      setDemoBusy(false);
    }
  }, [setAll, wsStatus]);

  const handleClear = useCallback(async () => {
    setActionError(null);
    try {
      await api.clearFlows();
      removeAll();
      queryClient.setQueryData(['flows', 'initial'], {
        flows: [],
        meta: { total: 0, hasMore: false, order: 'asc' },
      });
    } catch (error) {
      setActionError(errorMessage(error));
    }
  }, [queryClient, removeAll]);

  const handleRefresh = useCallback(async () => {
    setActionError(null);
    try {
      const data = await api.listFlows({ limit: 500, order: 'asc' });
      setAll(data.flows);
    } catch (error) {
      setActionError(errorMessage(error));
    }
  }, [setAll]);

  const handleExportHar = useCallback(async () => {
    setExporting(true);
    setActionError(null);
    try {
      await api.exportHar(filter);
    } catch (error) {
      setActionError(errorMessage(error));
    } finally {
      setExporting(false);
    }
  }, [filter]);

  const handleProxyChanged = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: ['proxy-status'] });
    void queryClient.invalidateQueries({ queryKey: ['system-info'] });
    void queryClient.invalidateQueries({ queryKey: ['cert-status'] });
  }, [queryClient]);

  const handleCaptureChanged = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: ['capture-status'] });
    void queryClient.invalidateQueries({ queryKey: ['system-info'] });
    void queryClient.invalidateQueries({ queryKey: ['packets'] });
    void queryClient.invalidateQueries({ queryKey: ['flows'] });
  }, [queryClient]);

  const combinedError =
    actionError ||
    (flowsQuery.isError ? errorMessage(flowsQuery.error) : null) ||
    (infoQuery.isError ? errorMessage(infoQuery.error) : null);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Shell
        info={infoQuery.data}
        infoLoading={infoQuery.isLoading}
        proxyStatus={proxyQuery.data}
        captureStatus={captureQuery.data}
        wsStatus={wsStatus}
        themeMode={mode}
        onToggleTheme={() => setMode((current) => (current === 'dark' ? 'light' : 'dark'))}
        onDemo={handleDemo}
        demoBusy={demoBusy}
        onClear={handleClear}
        onRefresh={handleRefresh}
        refreshing={flowsQuery.isFetching}
        onExportHar={handleExportHar}
        exporting={exporting}
        onProxyChanged={handleProxyChanged}
        onCaptureChanged={handleCaptureChanged}
        error={combinedError}
        onDismissError={() => setActionError(null)}
      />
    </ThemeProvider>
  );
}
