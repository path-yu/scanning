#!/usr/bin/env node
/**
 * 本地网易云 EAPI Mock 服务。
 *
 * 协议：
 *   请求体：params=<hex(AES-128-ECB(明文))>
 *   请求明文：/api/<接口名>-36cd479b6b5-<JSON>
 *   响应体：AES-128-ECB(PKCS7(JSON)) 原始密文
 *
 * 用法：
 *   node scripts/eapi-mock.mjs
 *   node scripts/eapi-mock.mjs --port 18080 --mocks scripts/eapi-mocks.json
 *   node scripts/eapi-mock.mjs --quiet
 *
 * 配置：
 *   scripts/eapi-mocks.json 中普通键为完整路径，值可以是 JSON 对象或字符串；
 *   "__default" 为未匹配路径的兜底响应；路径支持 "*" 通配。
 */

import { createCipheriv, createDecipheriv } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const KEY = Buffer.from('e82ckenh8dichen8', 'utf8');
const PROTOCOL_SEP = '-36cd479b6b5-';
const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const MAX_BODY_BYTES = 2 * 1024 * 1024;

const DEFAULT_RESPONSE = { code: 200, data: {}, message: '' };

function printHelp() {
  console.log(`本地网易云 EAPI Mock 服务

用法: node scripts/eapi-mock.mjs [选项]

选项:
  --host <addr>    监听地址，默认 127.0.0.1
  --port <port>    监听端口，默认 18080
  --mocks <file>   mock 配置路径，默认 scripts/eapi-mocks.json
  --quiet, -q      只输出启动信息和错误
  --help, -h       显示帮助

示例:
  node scripts/eapi-mock.mjs
  node scripts/eapi-mock.mjs --port 18081 --mocks ./my-mocks.json`);
}

function parseArgs(argv) {
  const opts = {
    host: '127.0.0.1',
    port: 18080,
    mocks: resolve(SCRIPT_DIR, 'eapi-mocks.json'),
    quiet: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--host':
        opts.host = argv[++i] || opts.host;
        break;
      case '--port':
        opts.port = Number(argv[++i]);
        break;
      case '--mocks':
        opts.mocks = resolve(process.cwd(), argv[++i] || '');
        break;
      case '--quiet':
      case '-q':
        opts.quiet = true;
        break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
        break;
      default:
        throw new Error(`未知参数: ${arg}`);
    }
  }
  if (!Number.isInteger(opts.port) || opts.port <= 0 || opts.port > 65535) {
    throw new Error(`端口无效: ${opts.port}`);
  }
  return opts;
}

function wildcardRegExp(pattern) {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
}

function normalizePath(pathname) {
  if (pathname.length > 1) return pathname.replace(/\/+$/, '');
  return pathname;
}

function loadMocks(file, quiet) {
  if (!existsSync(file)) {
    if (!quiet) console.warn(`[eapi-mock] 未找到配置 ${file}，使用内置兜底响应`);
    return { defaultResponse: DEFAULT_RESPONSE, routes: [] };
  }

  const raw = JSON.parse(readFileSync(file, 'utf8'));
  const defaultResponse = raw.__default ?? DEFAULT_RESPONSE;
  const routes = Object.entries(raw)
    .filter(([key]) => !key.startsWith('__'))
    .map(([path, response]) => {
      const pattern = normalizePath(path);
      return {
        path: pattern,
        response,
        exact: !pattern.includes('*'),
        matcher: pattern.includes('*') ? wildcardRegExp(pattern) : null,
      };
    })
    .sort((a, b) => {
      if (a.exact !== b.exact) return a.exact ? -1 : 1;
      return b.path.length - a.path.length;
    });

  return { defaultResponse, routes };
}

function matchRoute(routes, pathname) {
  for (const route of routes) {
    if (route.exact && route.path === pathname) return route;
  }
  for (const route of routes) {
    if (!route.exact && route.matcher?.test(pathname)) return route;
  }
  return null;
}

function pkcs7Unpad(data) {
  if (!data.length) return data;
  const padding = data[data.length - 1];
  if (padding < 1 || padding > 16 || padding > data.length) return data;
  for (let i = data.length - padding; i < data.length; i += 1) {
    if (data[i] !== padding) return data;
  }
  return data.subarray(0, data.length - padding);
}

function decryptEAPI(data) {
  if (!data.length || data.length % 16 !== 0) {
    throw new Error(`密文长度 ${data.length} 不是 16 的倍数`);
  }
  const decipher = createDecipheriv('aes-128-ecb', KEY, null);
  decipher.setAutoPadding(false);
  const plain = Buffer.concat([decipher.update(data), decipher.final()]);
  return pkcs7Unpad(plain);
}

function encryptEAPI(text) {
  const plain = Buffer.from(text, 'utf8');
  const padding = 16 - (plain.length % 16);
  const padded = Buffer.concat([plain, Buffer.alloc(padding, padding)]);
  const cipher = createCipheriv('aes-128-ecb', KEY, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(padded), cipher.final()]);
}

function extractJsonObject(text, start) {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === '{' || ch === '[') {
      depth += 1;
    } else if (ch === '}' || ch === ']') {
      depth -= 1;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return text.slice(start);
}

function extractRequest(plain) {
  const text = plain.toString('utf8');
  const marker = text.indexOf(PROTOCOL_SEP);
  const start = text.indexOf('{', marker >= 0 ? marker + PROTOCOL_SEP.length : 0);
  if (start < 0) return { json: null, text };
  // 明文在 JSON 之后还会带一段 -36cd479b6b5-<digest>，只截取完整 JSON 对象。
  const payload = extractJsonObject(text, start);
  try {
    return { json: JSON.parse(payload), text: payload };
  } catch {
    return { json: null, text: payload };
  }
}

function responseText(response) {
  if (typeof response === 'string') {
    // 字符串按原始 JSON 文本加密，便于直接粘贴大段响应。
    JSON.parse(response);
    return response;
  }
  return JSON.stringify(response);
}

async function readBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      throw new Error(`请求体超过 ${MAX_BODY_BYTES} 字节`);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function sendText(res, status, message, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(message);
}

function requestKeys(json) {
  if (!json || typeof json !== 'object') return '(non-json)';
  const keys = Object.keys(json).filter((key) => key !== 'header' && key !== 'e_r');
  return keys.length ? keys.join(',') : '(none)';
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const mocks = loadMocks(opts.mocks, opts.quiet);
  const startedAt = Date.now();

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      const pathname = normalizePath(url.pathname);

      if (req.method === 'GET' && (pathname === '/' || pathname === '/health')) {
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
        });
        res.end(JSON.stringify({
          ok: true,
          service: 'eapi-mock',
          routes: mocks.routes.length,
          uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
        }));
        return;
      }

      if (req.method !== 'POST' || !pathname.startsWith('/eapi/')) {
        sendText(res, 404, `仅支持 POST /eapi/*，收到 ${req.method} ${pathname}`);
        return;
      }

      let body;
      try {
        body = await readBody(req);
      } catch (cause) {
        sendText(res, 413, cause.message);
        return;
      }

      const params = new URLSearchParams(body);
      const hex = params.get('params');
      if (!hex) {
        sendText(res, 400, '缺少 params 字段');
        return;
      }
      if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
        sendText(res, 400, 'params 不是有效的十六进制密文');
        return;
      }

      let plain;
      try {
        plain = decryptEAPI(Buffer.from(hex, 'hex'));
      } catch (cause) {
        sendText(res, 400, `EAPI 解密失败: ${cause.message}`);
        return;
      }

      const request = extractRequest(plain);
      const route = matchRoute(mocks.routes, pathname);
      const response = route ? route.response : mocks.defaultResponse;
      const json = responseText(response);
      const cipher = encryptEAPI(json);

      if (!opts.quiet) {
        const routeLabel = route ? route.path : '__default';
        console.log(
          `[eapi-mock] ${new Date().toISOString()} ${pathname} -> ${routeLabel} | req=${requestKeys(request.json)} | resp=${Buffer.byteLength(json)}B/${cipher.length}B`,
        );
      }

      res.writeHead(200, {
        'Content-Type': 'text/plain;charset=UTF-8',
        'Content-Length': cipher.length,
        'Cache-Control': 'no-store',
        'X-EAPI-Mock': '1',
      });
      res.end(cipher);
    } catch (cause) {
      console.error(`[eapi-mock] 请求处理失败: ${cause.stack || cause.message}`);
      if (!res.headersSent) {
        sendText(res, 500, `EAPI mock error: ${cause.message}`);
      } else {
        res.end();
      }
    }
  });

  server.on('error', (cause) => {
    console.error(`[eapi-mock] 监听失败: ${cause.message}`);
    process.exit(1);
  });

  server.listen(opts.port, opts.host, () => {
    console.log(`[eapi-mock] 监听 http://${opts.host}:${opts.port}`);
    console.log(`[eapi-mock] 配置 ${opts.mocks}（${mocks.routes.length} 条路由 + __default）`);
    console.log('[eapi-mock] 在 Scanning 中用请求阶段规则 map_remote 指向该地址即可');
  });

  let closing = false;
  const shutdown = (signal) => {
    if (closing) return;
    closing = true;
    console.log(`\n[eapi-mock] 收到 ${signal}，正在停止...`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

try {
  main();
} catch (cause) {
  console.error(`[eapi-mock] 启动失败: ${cause.message}`);
  process.exit(1);
}
