import {
  Box,
  Button,
  CircularProgress,
  IconButton,
  InputBase,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Typography,
} from '@mui/material';
import type { RefObject } from 'react';
import { Close, DeleteOutline, DeleteSweepOutlined, HelpOutline, Search } from '@mui/icons-material';
import { formatNumber } from '@/lib/format';
import type { SearchScope } from '@/lib/filter';

interface FilterBarProps {
  value: string;
  onChange: (value: string) => void;
  count: number;
  total: number;
  error?: string;
  searching?: boolean;
  searchError?: string;
  inputRef: RefObject<HTMLInputElement | null>;
  searchScope: SearchScope;
  onSearchScopeChange: (scope: SearchScope) => void;
  selectionCount: number;
  hasFlows: boolean;
  onDeleteSelected: () => void;
  onClearAll: () => void;
}

const FILTER_HELP = `搜索模式：
URL：只匹配域名、路径、方法和完整 URL
请求：模糊搜索请求正文（JSON / 表单，含可解密的 EAPI params）
响应：模糊搜索响应正文（含解密的 EAPI/xeapi JSON）

直接输入关键字时按当前模式搜索，例如：
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
  searchScope,
  onSearchScopeChange,
  selectionCount,
  hasFlows,
  onDeleteSelected,
  onClearAll,
}: FilterBarProps) {
  const shownError = error || searchError;
  return (
    <Box
      sx={{
        height: 50,
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
          height: 34,
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
        <Search sx={{ fontSize: 17, color: shownError ? 'error.main' : 'text.disabled', flexShrink: 0 }} />
        <InputBase
          inputRef={inputRef}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') event.currentTarget.blur();
          }}
          placeholder={
            searchScope === 'request'
              ? '搜索请求正文（JSON / 表单，含解密内容）'
              : searchScope === 'response'
                ? '搜索响应正文（含解密 JSON）'
                : '搜索 URL（域名、路径、方法），或 method:POST…'
          }
          sx={{
            flex: 1,
            minWidth: 0,
            fontSize: 13.5,
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
              fontSize: 10.5,
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

      <Tooltip title="URL：匹配域名、路径和方法；请求/响应：模糊检索对应正文（含解密 JSON）">
        <Box component="span" sx={{ display: 'flex', flexShrink: 0 }}>
          <ToggleButtonGroup
            size="small"
            exclusive
            value={searchScope}
            onChange={(_, value: SearchScope | null) => {
              if (value) onSearchScopeChange(value);
            }}
            aria-label="搜索范围"
            sx={{
              height: 30,
              '& .MuiToggleButton-root': {
                px: 1.1,
                py: 0,
                fontSize: 11.5,
                fontWeight: 700,
                textTransform: 'none',
                color: 'text.secondary',
                borderColor: 'divider',
              },
              '& .MuiToggleButton-root.Mui-selected': {
                bgcolor: 'action.selected',
                color: 'primary.main',
              },
            }}
          >
            <ToggleButton value="url">URL</ToggleButton>
            <ToggleButton value="request">请求</ToggleButton>
            <ToggleButton value="response">响应</ToggleButton>
          </ToggleButtonGroup>
        </Box>
      </Tooltip>

      {searching ? (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, whiteSpace: 'nowrap' }}>
          <CircularProgress size={11} />
          <Typography sx={{ fontSize: 11, color: 'text.disabled' }}>
            {searchScope === 'request' ? '请求搜索中' : '响应搜索中'}
          </Typography>
        </Box>
      ) : null}

      {selectionCount > 0 ? (
        <Button
          size="small"
          color="error"
          variant="outlined"
          startIcon={<DeleteOutline sx={{ fontSize: 15 }} />}
          onClick={onDeleteSelected}
          sx={{ height: 30, flexShrink: 0, whiteSpace: 'nowrap' }}
        >
          删除选中 ({selectionCount})
        </Button>
      ) : null}

      <Tooltip title="清空当前会话全部请求">
        <span>
          <Button
            size="small"
            color="inherit"
            variant="outlined"
            startIcon={<DeleteSweepOutlined sx={{ fontSize: 15 }} />}
            onClick={onClearAll}
            disabled={!hasFlows}
            sx={{ height: 30, flexShrink: 0, whiteSpace: 'nowrap', display: { xs: 'none', md: 'inline-flex' } }}
          >
            清空
          </Button>
        </span>
      </Tooltip>

      {shownError ? (
        <Typography
          sx={{
            fontSize: 11.5,
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

      <Typography sx={{ fontSize: 12, color: 'text.secondary', whiteSpace: 'nowrap' }}>
        匹配 <Box component="span" className="mono" sx={{ color: 'text.primary', fontWeight: 600 }}>{formatNumber(count)}</Box>
        <Box component="span" sx={{ color: 'text.disabled' }}> / {formatNumber(total)}</Box>
      </Typography>

      <Tooltip title={<Box sx={{ whiteSpace: 'pre-line', fontSize: 11.5 }}>{FILTER_HELP}</Box>} placement="bottom-end">
        <IconButton size="small" aria-label="过滤语法帮助">
          <HelpOutline sx={{ fontSize: 15 }} />
        </IconButton>
      </Tooltip>
    </Box>
  );
}
