import { useMemo, type MouseEvent } from 'react';
import {
  Alert,
  AppBar,
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  IconButton,
  Toolbar,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import { Close, ContentCopy, Download } from '@mui/icons-material';
import ReactJson, { type ThemeObject } from '@microlink/react-json-view';
import { formatBytes } from '@/lib/format';

interface JsonViewerDialogProps {
  open: boolean;
  title: string;
  text: string;
  size?: number;
  loading?: boolean;
  error?: string;
  decrypted?: boolean;
  truncated?: boolean;
  downloadLabel?: string;
  onClose: () => void;
  onCopy?: () => void;
  onDownload?: () => void;
}

// 与应用的深色主题保持一致，避免 react-json-view 自带主题背景突兀。
const DARK_JSON_THEME: ThemeObject = {
  base00: '#0a0e13',
  base01: '#101720',
  base02: '#1e2a37',
  base03: '#5b6b7c',
  base04: '#8b97a6',
  base05: '#e6edf3',
  base06: '#f0f4f8',
  base07: '#ffffff',
  base08: '#f87171',
  base09: '#fbbf24',
  base0A: '#fbbf24',
  base0B: '#34d399',
  base0C: '#38bdf8',
  base0D: '#38bdf8',
  base0E: '#a78bfa',
  base0F: '#f97316',
};

const URL_PATTERN = /^(https?:\/\/|\/\/)[^\s"'<>]+$/i;

export function JsonViewerDialog({
  open,
  title,
  text,
  size,
  loading,
  error,
  decrypted,
  truncated,
  downloadLabel,
  onClose,
  onCopy,
  onDownload,
}: JsonViewerDialogProps) {
  const theme = useTheme();

  const parsed = useMemo(() => {
    const trimmed = text.trim();
    if (!trimmed) {
      return { value: null as object | null, error: text ? '' : '正文为空' };
    }
    try {
      const value = JSON.parse(trimmed) as unknown;
      if (value !== null && typeof value === 'object') {
        return { value: value as object, error: '' };
      }
      // react-json-view 只接受对象，原始类型包一层再展示。
      return { value: { value }, error: '' };
    } catch (cause) {
      return {
        value: null as object | null,
        error: cause instanceof Error ? cause.message : '不是有效 JSON',
      };
    }
  }, [text]);

  // 捕获阶段拦截 URL 文本点击，避免 react-json-view 同时触发展开/收起。
  const handleLinkClick = (event: MouseEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement;
    if (target.closest('button, a, input, textarea')) return;
    const raw = (target.textContent ?? '').trim().replace(/^["']|["']$/g, '');
    if (!URL_PATTERN.test(raw)) return;
    event.preventDefault();
    event.stopPropagation();
    const href = raw.startsWith('//') ? `https:${raw}` : raw;
    window.open(href, '_blank', 'noopener,noreferrer');
  };

  return (
    <Dialog open={open} onClose={onClose} fullScreen>
      <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column', bgcolor: 'background.default' }}>
        <AppBar
          position="static"
          color="transparent"
          elevation={0}
          sx={{ bgcolor: 'background.paper', borderBottom: '1px solid', borderColor: 'divider', flexShrink: 0 }}
        >
          <Toolbar variant="dense" sx={{ gap: 1, minHeight: 48 }}>
            <Typography sx={{ fontSize: 13, fontWeight: 700 }}>{title}</Typography>
            {decrypted ? <Chip size="small" label="EAPI 已解密" color="info" variant="outlined" /> : null}
            {truncated ? <Chip size="small" label="正文已截断" color="warning" variant="outlined" /> : null}
            {size ? (
              <Typography className="mono" sx={{ fontSize: 10, color: 'text.disabled' }}>
                {formatBytes(size)}
              </Typography>
            ) : null}
            <Box sx={{ flex: 1 }} />
            <Typography sx={{ fontSize: 10, color: 'text.disabled', display: { xs: 'none', md: 'block' } }}>
              JSON 中的 http(s) 链接可直接点击打开
            </Typography>
            {onCopy ? (
              <Tooltip title="复制正文">
                <IconButton size="small" onClick={onCopy} aria-label="复制正文">
                  <ContentCopy sx={{ fontSize: 15 }} />
                </IconButton>
              </Tooltip>
            ) : null}
            {onDownload ? (
              <Button
                size="small"
                variant="outlined"
                startIcon={<Download sx={{ fontSize: 14 }} />}
                onClick={onDownload}
                sx={{ height: 28 }}
              >
                {downloadLabel || '下载 JSON'}
              </Button>
            ) : null}
            <IconButton size="small" onClick={onClose} aria-label="关闭全屏 JSON">
              <Close sx={{ fontSize: 17 }} />
            </IconButton>
          </Toolbar>
        </AppBar>

        <Box sx={{ flex: 1, minHeight: 0, overflow: 'auto', p: 2 }}>
          {loading ? (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, p: 2 }}>
              <CircularProgress size={16} />
              <Typography sx={{ fontSize: 12, color: 'text.secondary' }}>正在加载完整正文…</Typography>
            </Box>
          ) : error ? (
            <Alert severity="error" variant="outlined">
              {error}
            </Alert>
          ) : parsed.error ? (
            <>
              <Alert severity="warning" variant="outlined" sx={{ mb: 1.5 }}>
                JSON 解析失败：{parsed.error}。以下为原始正文。
              </Alert>
              <Box
                component="pre"
                className="mono"
                sx={{
                  m: 0,
                  fontSize: 11,
                  lineHeight: 1.7,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  color: 'text.secondary',
                }}
              >
                {text}
              </Box>
            </>
          ) : parsed.value ? (
            <Box
              className="mono"
              onClickCapture={handleLinkClick}
              sx={{ fontSize: 12.5, '& a': { color: 'primary.main' } }}
            >
              <ReactJson
                src={parsed.value}
                name={false}
                theme={theme.palette.mode === 'dark' ? DARK_JSON_THEME : 'rjv-default'}
                collapsed={2}
                displayDataTypes={false}
                displayObjectSize
                enableClipboard={false}
                quotesOnKeys={false}
                indentWidth={18}
                groupArraysAfterLength={50}
                iconStyle="triangle"
                style={{
                  background: 'transparent',
                  fontFamily: 'inherit',
                  fontSize: 12.5,
                  lineHeight: 1.6,
                }}
              />
            </Box>
          ) : null}
        </Box>
      </Box>
    </Dialog>
  );
}
