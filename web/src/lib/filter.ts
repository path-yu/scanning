import type { FlowSummary } from '@/types';

export type FilterPredicate = (flow: FlowSummary) => boolean;

export interface FilterResult {
  predicate: FilterPredicate;
  error?: string;
}

const alwaysTrue: FilterPredicate = () => true;
const comparisonRe = /^([A-Za-z][A-Za-z0-9_.-]*)(>=|<=|!=|!~|=|>|<|~)(.+)$/;

export function compileFilter(expr: string): FilterResult {
  const input = expr.trim();
  if (!input) return { predicate: alwaysTrue };
  if (input.includes('(') || input.includes(')')) {
    return { predicate: alwaysTrue, error: 'M0 过滤语法暂不支持括号' };
  }

  const orSplit = splitLogical(input, 'or');
  if (orSplit.error) return { predicate: alwaysTrue, error: orSplit.error };

  const groups: FilterPredicate[] = [];
  for (const orPart of orSplit.parts) {
    const andSplit = splitLogical(orPart, 'and');
    if (andSplit.error) return { predicate: alwaysTrue, error: andSplit.error };

    const terms: FilterPredicate[] = [];
    for (const raw of andSplit.parts) {
      const term = raw.trim();
      if (!term) continue;
      let negate = false;
      let body = term;
      if (body.toLowerCase().startsWith('not ')) {
        negate = true;
        body = body.slice(4).trim();
      }
      const compiled = compileTerm(body);
      if (typeof compiled === 'string') {
        return { predicate: alwaysTrue, error: compiled };
      }
      terms.push(negate ? (flow) => !compiled(flow) : compiled);
    }
    if (terms.length) {
      groups.push((flow) => terms.every((term) => term(flow)));
    }
  }

  if (!groups.length) return { predicate: alwaysTrue };
  return { predicate: (flow) => groups.some((group) => group(flow)) };
}

// plainKeyword 判断过滤表达式是否为单一自由关键字，若是则返回该关键字。
// 只有这种形式会触发服务端正文全文搜索。
export function plainKeyword(expr: string): string | null {
  const input = expr.trim();
  if (!input) return null;
  if (/[:()]/.test(input)) return null;
  if (/(^|\s)(and|or|not)(\s|$)/i.test(input)) return null;
  const keyword = unquote(input).trim();
  return keyword || null;
}

function compileTerm(term: string): FilterPredicate | string {
  const operatorMatch = comparisonRe.exec(term);
  if (operatorMatch) {
    return compileField(operatorMatch[1], operatorMatch[2], unquote(operatorMatch[3].trim()));
  }

  const colon = term.indexOf(':');
  if (colon > 0) {
    const field = term.slice(0, colon);
    let rest = term.slice(colon + 1).trim();
    let op = '=';
    for (const candidate of ['>=', '<=', '!=', '!~', '>', '<', '=', '~']) {
      if (rest.startsWith(candidate)) {
        op = candidate;
        rest = rest.slice(candidate.length).trim();
        break;
      }
    }
    if (!rest) return `过滤条件「${term}」缺少值`;
    return compileField(field, op, unquote(rest));
  }

  const needle = unquote(term).toLowerCase();
  return (flow) =>
    flow.host.toLowerCase().includes(needle) ||
    flow.path.toLowerCase().includes(needle) ||
    flow.method.toLowerCase().includes(needle);
}

function compileField(field: string, op: string, value: string): FilterPredicate | string {
  const name = field.toLowerCase();
  const negative = op === '!=' || op === '!~';

  switch (name) {
    case 'method': {
      const values = value.split(',').map((item) => item.trim().toUpperCase()).filter(Boolean);
      return (flow) => {
        const matched = values.includes(flow.method.toUpperCase());
        return negative ? !matched : matched;
      };
    }
    case 'host':
    case 'path':
    case 'url':
    case 'mime': {
      const match = globPredicate(value);
      return (flow) => {
        let actual = '';
        switch (name) {
          case 'host':
            actual = flow.host;
            break;
          case 'path':
            actual = flow.path;
            break;
          case 'url':
            actual = urlOf(flow);
            break;
          case 'mime':
            actual = flow.mime;
            break;
        }
        const matched = match(actual);
        return negative ? !matched : matched;
      };
    }
    case 'scheme':
    case 'mode':
    case 'state':
    case 'app':
    case 'process':
    case 'origin':
    case 'ip': {
      const needle = value.toLowerCase();
      return (flow) => {
        let actual = '';
        switch (name) {
          case 'scheme':
            actual = flow.scheme;
            break;
          case 'mode':
            actual = flow.mode;
            break;
          case 'state':
            actual = flow.state;
            break;
          case 'app':
          case 'process':
            actual = flow.client.app ?? '';
            break;
          case 'origin':
            actual = flow.client.origin ?? '';
            break;
          case 'ip':
            actual = flow.client.ip;
            break;
        }
        const matched = actual.toLowerCase().includes(needle);
        return negative ? !matched : matched;
      };
    }
    case 'status': {
      const range = parseStatusRange(value);
      if (range !== null) {
        return (flow) => {
          const matched = Math.floor(flow.statusCode / 100) === range;
          return negative ? !matched : matched;
        };
      }
      const target = Number(value.trim());
      if (!Number.isFinite(target)) return `status 值无效: ${value}`;
      return (flow) => compareNumber(flow.statusCode, target, op);
    }
    case 'size':
    case 'reqsize':
    case 'respsize': {
      const target = parseBytes(value);
      if (target === null) return `大小值无效: ${value}`;
      return (flow) => {
        const actual =
          name === 'size'
            ? flow.reqSize + flow.respSize
            : name === 'reqsize'
              ? flow.reqSize
              : flow.respSize;
        return compareNumber(actual, target, op);
      };
    }
    case 'duration': {
      const target = parseMillis(value);
      if (target === null) return `耗时值无效: ${value}`;
      return (flow) => compareNumber(flow.durationMs, target, op);
    }
    case 'tag': {
      const needle = value.toLowerCase();
      return (flow) => {
        const matched = (flow.tags ?? []).some((tag) => tag.toLowerCase() === needle);
        return negative ? !matched : matched;
      };
    }
    case 'port': {
      const target = Number(value.trim());
      if (!Number.isFinite(target)) return `port 值无效: ${value}`;
      return (flow) => flow.port === target || flow.client.port === target;
    }
    case 'body':
      return 'M0 列表过滤暂不支持 body，请在详情页查看正文';
    default:
      return `未知过滤字段: ${field}`;
  }
}

function splitLogical(expr: string, keyword: string): { parts: string[]; error?: string } {
  const parts: string[] = [];
  let buffer = '';
  let inQuote = false;
  let quote = '';

  for (let i = 0; i < expr.length; i += 1) {
    const ch = expr[i];
    if (inQuote) {
      buffer += ch;
      if (ch === quote) inQuote = false;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inQuote = true;
      quote = ch;
      buffer += ch;
      continue;
    }
    if (matchesKeyword(expr, i, keyword)) {
      parts.push(buffer);
      buffer = '';
      i += keyword.length - 1;
      continue;
    }
    buffer += ch;
  }

  if (inQuote) return { parts: [], error: '过滤表达式引号未闭合' };
  parts.push(buffer);
  return { parts };
}

function matchesKeyword(expr: string, index: number, keyword: string): boolean {
  if (expr.slice(index, index + keyword.length).toLowerCase() !== keyword) return false;
  const previous = index === 0 ? ' ' : expr[index - 1];
  const nextIndex = index + keyword.length;
  const next = nextIndex >= expr.length ? ' ' : expr[nextIndex];
  return /\s/.test(previous) && /\s/.test(next);
}

function globPredicate(pattern: string): (value: string) => boolean {
  const lower = pattern.toLowerCase();
  if (!/[*?]/.test(lower)) {
    return (value) => value.toLowerCase().includes(lower);
  }
  const escaped = escapeRegExp(lower).replace(/\\\*/g, '.*').replace(/\\\?/g, '.');
  const re = new RegExp(`^${escaped}$`);
  return (value) => re.test(value.toLowerCase());
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function unquote(value: string): string {
  if (value.length >= 2) {
    const first = value[0];
    const last = value[value.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return value.slice(1, -1);
    }
  }
  return value;
}

function parseStatusRange(value: string): number | null {
  const match = /^([1-5])xx$/i.exec(value.trim());
  return match ? Number(match[1]) : null;
}

function parseBytes(value: string): number | null {
  let text = value.trim().toLowerCase();
  let multiplier = 1;
  if (text.endsWith('kb')) {
    multiplier = 1024;
    text = text.slice(0, -2);
  } else if (text.endsWith('mb')) {
    multiplier = 1024 * 1024;
    text = text.slice(0, -2);
  } else if (text.endsWith('gb')) {
    multiplier = 1024 * 1024 * 1024;
    text = text.slice(0, -2);
  }
  const number = Number(text);
  return Number.isFinite(number) ? number * multiplier : null;
}

function parseMillis(value: string): number | null {
  let text = value.trim().toLowerCase();
  let multiplier = 1;
  if (text.endsWith('ms')) {
    text = text.slice(0, -2);
  } else if (text.endsWith('s')) {
    multiplier = 1000;
    text = text.slice(0, -1);
  }
  const number = Number(text);
  return Number.isFinite(number) ? number * multiplier : null;
}

function compareNumber(actual: number, target: number, op: string): boolean {
  switch (op) {
    case '>':
      return actual > target;
    case '>=':
      return actual >= target;
    case '<':
      return actual < target;
    case '<=':
      return actual <= target;
    case '!=':
    case '!~':
      return actual !== target;
    default:
      return actual === target;
  }
}

export function urlOf(flow: FlowSummary): string {
  const defaultPort =
    (flow.scheme === 'http' && flow.port === 80) ||
    (flow.scheme === 'https' && flow.port === 443) ||
    (flow.scheme === 'ws' && flow.port === 80) ||
    (flow.scheme === 'wss' && flow.port === 443) ||
    !flow.port;
  return `${flow.scheme || 'http'}://${flow.host}${defaultPort ? '' : `:${flow.port}`}${flow.path}`;
}
