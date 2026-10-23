import { Box, CircularProgress, IconButton, InputBase, Tooltip, Typography } from '@mui/material';
import type { RefObject } from 'react';
import { Close, HelpOutline, Search } from '@mui/icons-material';
import { formatNumber } from '@/lib/format';

interface FilterBarProps {
  value: string;
  onChange: (value: string) => void;
  count: number;
  total: number;
  error?: string;
  searching?: boolean;
  searchError?: string;
  inputRef: RefObject<HTMLInputElement | null>;
}

const FILTER_HELP = `支持字段：method / host / path / url / status / mime / scheme / mode / app / tag / duration / size
直接输入关键字会同时搜索 URL、请求/响应头和正文，例如：
Taylor Swift
组合示例：
method:POST and status:>=400
host:*.example.com
mime:application/json
duration:>300ms
not mime:image/*`;

export function FilterBar({
  value,
  onChange,
  count,
  total,
  error,
  searching,
  searchError,
  inputRef,
}: FilterBarProps) {
  const shownError = error || searchError;
  return (
    <Box
      sx={{
        height: 44,
        px: 1.5,
        display: 'flex',
        alignItems: 'center',
        gap: 1,
        borderBottom: '1px solid',
        borderColor: 'divider',
        flexShrink: 0,
      }}
    >
      <Box
        sx={{
          flex: 1,
          minWidth: 0,
          height: 30,
          px: 1,
          display: 'flex',
          alignItems: 'center',
          gap: 0.75,
          borderRadius: 1,
          border: '1px solid',
          borderColor: shownError ? 'error.main' : 'divider',
          bgcolor: 'action.hover',
          transition: 'border-color 120ms ease',
        }}
      >
        <Search sx={{ fontSize: 15, color: shownError ? 'error.main' : 'text.disabled', flexShrink: 0 }} />
        <InputBase
          inputRef={inputRef}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') event.currentTarget.blur();
          }}
          placeholder="搜索 URL、请求/响应内容，或 method:POST and status:>=400"
          sx={{
            flex: 1,
            minWidth: 0,
            fontSize: 12,
            '& input': { py: 0.4, px: 0 },
          }}
          inputProps={{ 'aria-label': '过滤流量' }}
        />
        {value ? (
          <IconButton size="small" onClick={() => onChange('')} aria-label="清空过滤">
            <Close sx={{ fontSize: 14 }} />
          </IconButton>
        ) : (
          <Box
            component="span"
            className="mono"
            sx={{
              fontSize: 9.5,
              color: 'text.disabled',
              border: '1px solid',
              borderColor: 'divider',
              borderRadius: 0.5,
              px: 0.5,
              lineHeight: 1.5,
              flexShrink: 0,
              display: { xs: 'none', md: 'inline-block' },
            }}
          >
            /
          </Box>
        )}
      </Box>

      {searching ? (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, whiteSpace: 'nowrap' }}>
          <CircularProgress size={10} />
          <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>正文搜索中</Typography>
        </Box>
      ) : null}

      {shownError ? (
        <Typography
          sx={{
            fontSize: 10.5,
            color: 'error.main',
            maxWidth: 240,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            display: { xs: 'none', md: 'block' },
          }}
          title={shownError}
        >
          {shownError}
        </Typography>
      ) : null}

      <Typography sx={{ fontSize: 10.5, color: 'text.secondary', whiteSpace: 'nowrap' }}>
        匹配 <Box component="span" className="mono" sx={{ color: 'text.primary', fontWeight: 600 }}>{formatNumber(count)}</Box>
        <Box component="span" sx={{ color: 'text.disabled' }}> / {formatNumber(total)}</Box>
      </Typography>

      <Tooltip title={<Box sx={{ whiteSpace: 'pre-line', fontSize: 10.5 }}>{FILTER_HELP}</Box>} placement="bottom-end">
        <IconButton size="small" aria-label="过滤语法帮助">
          <HelpOutline sx={{ fontSize: 15 }} />
        </IconButton>
      </Tooltip>
    </Box>
  );
}
