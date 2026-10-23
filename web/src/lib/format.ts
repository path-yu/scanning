import dayjs from 'dayjs';

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value >= 100 || index === 0 ? Math.round(value) : value.toFixed(1)} ${units[index]}`;
}

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '0ms';
  if (ms < 1) return '<1ms';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(ms >= 10_000 ? 1 : 2)}s`;
}

export function formatTime(iso: string): string {
  if (!iso) return '--:--:--';
  return dayjs(iso).format('HH:mm:ss.SSS');
}

export function formatDateTime(iso: string): string {
  if (!iso) return '—';
  return dayjs(iso).format('YYYY-MM-DD HH:mm:ss');
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat('zh-CN').format(value);
}

export function statusColor(code: number): string {
  if (code >= 500) return '#f87171';
  if (code >= 400) return '#fbbf24';
  if (code >= 300) return '#38bdf8';
  if (code >= 200) return '#34d399';
  if (code > 0) return '#a78bfa';
  return '#94a3b8';
}

export function statusText(code: number): string {
  const map: Record<number, string> = {
    101: 'Switching Protocols',
    200: 'OK',
    201: 'Created',
    204: 'No Content',
    301: 'Moved Permanently',
    302: 'Found',
    304: 'Not Modified',
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    409: 'Conflict',
    422: 'Unprocessable Entity',
    429: 'Too Many Requests',
    500: 'Internal Server Error',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
  };
  return map[code] ?? (code > 0 ? '' : 'Pending');
}

export function methodColor(method: string): string {
  switch (method.toUpperCase()) {
    case 'GET':
      return '#38bdf8';
    case 'POST':
      return '#34d399';
    case 'PUT':
    case 'PATCH':
      return '#fbbf24';
    case 'DELETE':
      return '#f87171';
    case 'OPTIONS':
    case 'HEAD':
      return '#a78bfa';
    default:
      return '#94a3b8';
  }
}

export function mimeLabel(mime: string): string {
  if (!mime) return '—';
  if (mime.includes('json')) return 'JSON';
  if (mime.includes('html')) return 'HTML';
  if (mime.includes('javascript')) return 'JS';
  if (mime.includes('css')) return 'CSS';
  if (mime.startsWith('image/')) return 'IMG';
  if (mime.includes('font')) return 'FONT';
  if (mime.includes('event-stream')) return 'SSE';
  if (mime.startsWith('text/')) return 'TEXT';
  if (mime.includes('protobuf')) return 'PROTO';
  return 'BIN';
}

export function prettyBody(preview: string, mime: string): string {
  if (!preview) return '';
  if (mime.includes('json')) {
    try {
      return JSON.stringify(JSON.parse(preview), null, 2);
    } catch {
      return preview;
    }
  }
  return preview;
}

export function shortenPath(path: string, max = 120): string {
  if (path.length <= max) return path;
  return `${path.slice(0, max - 1)}…`;
}
