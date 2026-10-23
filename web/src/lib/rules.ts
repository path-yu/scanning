import type { Header, Rule, RuleAction, RuleMatch } from '@/types';

const ACTION_LABELS: Record<RuleAction['type'], string> = {
  mock: '返回 Mock',
  block: '阻断',
  delay: '延迟',
  map_remote: '转发到',
  rewrite_request: '改写请求',
  rewrite_response: '改写响应',
  pause: '断点暂停',
};

export function actionLabel(action: RuleAction): string {
  const label = ACTION_LABELS[action.type] ?? action.type;
  switch (action.type) {
    case 'mock':
      return `${label} ${action.status ?? 200}`;
    case 'block':
      return `${label} ${action.status ?? 403}`;
    case 'delay':
      return `${label} ${action.delayMs ?? 0}ms`;
    case 'map_remote':
      return `${label} ${action.remote ?? ''}`;
    default:
      return label;
  }
}

export function matchSummary(match: RuleMatch): string {
  const parts: string[] = [];
  if (match.methods?.length) parts.push(match.methods.join('/'));
  if (match.host) parts.push(match.host);
  if (match.path) parts.push(match.path);
  if (match.status) parts.push(`status:${match.status}`);
  if (match.mime) parts.push(match.mime);
  if (match.headerName) parts.push(`${match.headerName}${match.headerValue ? `~${match.headerValue}` : ''}`);
  if (match.bodyContains) parts.push(`body~${match.bodyContains}`);
  return parts.length ? parts.join(' · ') : '匹配全部请求';
}

export function ruleSummary(rule: Rule): string {
  return rule.actions.map(actionLabel).join(' + ');
}

export function headersToText(headers?: Header[]): string {
  return (headers ?? []).map((header) => `${header.name}: ${header.value}`).join('\n');
}

export function textToHeaders(text: string): Header[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const index = line.indexOf(':');
      if (index <= 0) return { name: line, value: '' };
      return { name: line.slice(0, index).trim(), value: line.slice(index + 1).trim() };
    })
    .filter((header) => header.name.length > 0);
}

export function methodsToText(methods?: string[]): string {
  return (methods ?? []).join(', ');
}

export function textToMethods(text: string): string[] {
  return text
    .split(',')
    .map((item) => item.trim().toUpperCase())
    .filter(Boolean);
}
