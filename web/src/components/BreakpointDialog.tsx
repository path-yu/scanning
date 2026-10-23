import { useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  Tooltip,
  Typography,
} from '@mui/material';
import { Close, EditOutlined, PlayArrow, Stop, TouchApp } from '@mui/icons-material';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api';
import { ResumeEditorDialog } from '@/components/ResumeEditorDialog';
import { formatTime, methodColor } from '@/lib/format';
import { urlOf } from '@/lib/filter';
import type { FlowSummary } from '@/types';

interface BreakpointDialogProps {
  open: boolean;
  pausedFlows: FlowSummary[];
  onClose: () => void;
  onSelect: (id: string) => void;
  onResumed: () => void;
}

export function BreakpointDialog({ open, pausedFlows, onClose, onSelect, onResumed }: BreakpointDialogProps) {
  const queryClient = useQueryClient();
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<FlowSummary | null>(null);

  const listQuery = useQuery({
    queryKey: ['breakpoints'],
    queryFn: api.listBreakpoints,
    enabled: open,
    refetchInterval: open ? 2000 : false,
  });

  const flows = listQuery.data ?? pausedFlows;

  const resume = async (flow: FlowSummary, action: 'forward' | 'abort' | 'mock') => {
    setBusyId(flow.id);
    setError(null);
    try {
      await api.resumeFlow(flow.id, {
        action,
        ...(action === 'mock'
          ? { status: 200, headers: [{ name: 'Content-Type', value: 'application/json' }], body: '{"mock":true}' }
          : {}),
      });
      await queryClient.invalidateQueries({ queryKey: ['breakpoints'] });
      await queryClient.invalidateQueries({ queryKey: ['flow', flow.id] });
      onResumed();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <>
      <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pr: 1 }}>
        <Box sx={{ flex: 1, fontSize: 15, fontWeight: 700 }}>断点队列</Box>
        <Chip size="small" label={`${flows.length} 个等待中`} color={flows.length ? 'warning' : 'default'} variant="outlined" />
        <IconButton size="small" onClick={onClose} aria-label="关闭">
          <Close sx={{ fontSize: 16 }} />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ pt: 0.5, pb: 1 }}>
        {error ? <Alert severity="error" sx={{ mb: 1.25 }}>{error}</Alert> : null}
        <Alert severity="info" variant="outlined" sx={{ mb: 1.25, py: 0.25 }}>
          断点等待超时后会自动放行，避免客户端一直挂起。放行后请求会继续按规则执行。
        </Alert>

        {listQuery.isLoading && !flows.length ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
            <CircularProgress size={18} />
          </Box>
        ) : flows.length === 0 ? (
          <Box
            sx={{
              py: 4,
              textAlign: 'center',
              color: 'text.disabled',
              fontSize: 12,
              border: '1px dashed',
              borderColor: 'divider',
              borderRadius: 1,
            }}
          >
            当前没有等待中的断点。
          </Box>
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {flows.map((flow) => (
              <Box
                key={flow.id}
                sx={{
                  border: '1px solid',
                  borderColor: 'divider',
                  borderRadius: 1.25,
                  p: 1.25,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 1,
                }}
              >
                <Box
                  component="span"
                  sx={{ fontSize: 10, fontWeight: 800, color: methodColor(flow.method), width: 46, flexShrink: 0 }}
                >
                  {flow.method}
                </Box>
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Typography className="mono" sx={{ fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {urlOf(flow)}
                  </Typography>
                  <Typography sx={{ fontSize: 10, color: 'text.disabled', mt: 0.3 }}>
                    暂停于 {formatTime(flow.startedAt)} · {flow.id.slice(-8)}
                  </Typography>
                </Box>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<TouchApp sx={{ fontSize: 13 }} />}
                  onClick={() => {
                    onSelect(flow.id);
                    onClose();
                  }}
                >
                  查看
                </Button>
                <Tooltip title="编辑请求/响应后放行">
                  <IconButton size="small" onClick={() => setEditing(flow)} disabled={busyId !== null}>
                    <EditOutlined sx={{ fontSize: 15 }} />
                  </IconButton>
                </Tooltip>
                <Button
                  size="small"
                  variant="contained"
                  startIcon={busyId === flow.id ? <CircularProgress size={12} color="inherit" /> : <PlayArrow sx={{ fontSize: 14 }} />}
                  onClick={() => void resume(flow, 'forward')}
                  disabled={busyId !== null}
                >
                  放行
                </Button>
                <Button
                  size="small"
                  color="secondary"
                  variant="outlined"
                  onClick={() => void resume(flow, 'mock')}
                  disabled={busyId !== null}
                >
                  Mock
                </Button>
                <Button
                  size="small"
                  color="error"
                  variant="outlined"
                  startIcon={<Stop sx={{ fontSize: 13 }} />}
                  onClick={() => void resume(flow, 'abort')}
                  disabled={busyId !== null}
                >
                  中止
                </Button>
              </Box>
            ))}
          </Box>
        )}
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose}>关闭</Button>
      </DialogActions>
      </Dialog>

      <ResumeEditorDialog
        open={Boolean(editing)}
        flowId={editing?.id ?? null}
        onClose={() => setEditing(null)}
        onResumed={() => {
          setEditing(null);
          void queryClient.invalidateQueries({ queryKey: ['breakpoints'] });
          onResumed();
        }}
      />
    </>
  );
}

function messageOf(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  return '操作失败';
}
