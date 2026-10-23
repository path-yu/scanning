import type { CaptureStatus, FlowSummary, Stats, WsEvent } from '@/types';

export type ConnectionStatus = 'connecting' | 'open' | 'closed';

interface EventHandlers {
  onFlows: (flows: FlowSummary[]) => void;
  onStats: (stats: Stats) => void;
  onStatus: (status: ConnectionStatus) => void;
  onCleared?: () => void;
  onDeleted?: (ids: string[]) => void;
  onCaptureStatus?: (status: CaptureStatus) => void;
}

export function connectEvents(handlers: EventHandlers): () => void {
  let socket: WebSocket | null = null;
  let attempt = 0;
  let disposed = false;
  let reconnectTimer: number | undefined;
  let frame = 0;

  let pendingFlows: FlowSummary[] = [];
  let pendingStats: Stats | null = null;

  const flush = () => {
    frame = 0;
    if (pendingFlows.length) {
      const flows = pendingFlows;
      pendingFlows = [];
      handlers.onFlows(flows);
    }
    if (pendingStats) {
      const stats = pendingStats;
      pendingStats = null;
      handlers.onStats(stats);
    }
  };

  const schedule = () => {
    if (!frame) frame = requestAnimationFrame(flush);
  };

  const connect = () => {
    if (disposed) return;
    handlers.onStatus('connecting');
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    socket = new WebSocket(`${protocol}://${window.location.host}/api/v1/events`);

    socket.onopen = () => {
      attempt = 0;
      handlers.onStatus('open');
      socket?.send(JSON.stringify({
        type: 'subscribe',
        data: { includeBodyChunks: false },
      }));
    };

    socket.onmessage = (message) => {
      let event: WsEvent;
      try {
        event = JSON.parse(message.data as string) as WsEvent;
      } catch {
        return;
      }

      switch (event.type) {
        case 'flow.created':
        case 'flow.updated':
        case 'flow.completed':
          if (event.data) pendingFlows.push(event.data as FlowSummary);
          schedule();
          break;
        case 'flow.paused':
        case 'flow.resumed': {
          const payload = event.data as { flow?: FlowSummary } | undefined;
          if (payload?.flow) pendingFlows.push(payload.flow);
          schedule();
          break;
        }
        case 'stats':
          if (event.data) pendingStats = event.data as Stats;
          schedule();
          break;
        case 'capture.status':
          if (event.data) handlers.onCaptureStatus?.(event.data as CaptureStatus);
          break;
        case 'flows.cleared':
          handlers.onCleared?.();
          break;
        case 'flows.deleted': {
          const payload = event.data as { ids?: string[] } | undefined;
          if (payload?.ids?.length) handlers.onDeleted?.(payload.ids);
          break;
        }
        default:
          break;
      }
    };

    socket.onclose = () => {
      handlers.onStatus('closed');
      if (disposed) return;
      const delay = Math.min(30_000, 1000 * 2 ** attempt) + Math.random() * 250;
      attempt += 1;
      reconnectTimer = window.setTimeout(connect, delay);
    };

    socket.onerror = () => {
      socket?.close();
    };
  };

  connect();

  return () => {
    disposed = true;
    if (frame) cancelAnimationFrame(frame);
    if (reconnectTimer) window.clearTimeout(reconnectTimer);
    socket?.close();
  };
}
