import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  TextField,
  Typography,
} from '@mui/material';
import { Close } from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import { headersToText, textToHeaders } from '@/lib/rules';
import type { Flow } from '@/types';

interface ResumeEditorDialogProps {
  open: boolean;
  flowId: string | null;
  onClose: () => void;
  onResumed: () => void;
}

// ResumeEditorDialog 允许在放行断点前改写请求或响应。
export function ResumeEditorDialog({ open, flowId, onClose, onResumed }: ResumeEditorDialogProps) {
  const [method, setMethod] = useState('GET');
  const [path, setPath] = useState('/');
  const [status, setStatus] = useState('');
  const [headers, setHeaders] = useState('');
  const [body, setBody] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const flowQuery = useQuery({
    queryKey: ['flow', flowId],
    queryFn: () => api.getFlow(flowId as string),
    enabled: open && Boolean(flowId),
  });

  const flow: Flow | undefined = flowQuery.data;
  const phase: 'request' | 'response' = flow && flow.statusCode > 0 ? 'response' : 'request';

  useEffect(() => {
    if (!open || !flow) return;
    const sourceHeaders = flow.statusCode > 0 ? flow.response?.headers : flow.request?.headers;
    setMethod(flow.method);
    setPath(flow.path);
    setStatus(String(flow.statusCode || ''));
    setHeaders(
      headersToText(
        (sourceHeaders ?? []).filter(
          (header) => !['host', 'content-length', 'connection'].includes(header.name.toLowerCase()),
        ),
      ),
    );
    setBody('');
    setError(null);
    // 仅在打开或切换 Flow 时重置。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, flow?.id]);

  const submit = async () => {
    if (!flow) return;
    setBusy(true);
    setError(null);
    try {
      await api.resumeFlow(flow.id, {
        action: 'forward',
        method: phase === 'request' ? method : undefined,
        path: phase === 'request' ? path : undefined,
        status: phase === 'response' && status ? Number(status) : undefined,
        headers: textToHeaders(headers),
        body: body === '' ? undefined : body,
      });
      onResumed();
      onClose();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '放行失败');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pr: 1 }}>
        <Box sx={{ flex: 1, fontSize: 15, fontWeight: 700 }}>
          编辑并放行 · {phase === 'request' ? '请求阶段' : '响应阶段'}
        </Box>
        <IconButton size="small" onClick={onClose} aria-label="关闭">
          <Close sx={{ fontSize: 16 }} />
        </IconButton>
      </DialogTitle>
      <DialogContent sx={{ pt: 0.5, pb: 1 }}>
        {flowQuery.isLoading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
            <CircularProgress size={18} />
          </Box>
        ) : !flow ? (
          <Alert severity="error">Flow 已不存在或已被淘汰。</Alert>
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.25 }}>
            {error ? <Alert severity="error">{error}</Alert> : null}

            {phase === 'request' ? (
              <Box sx={{ display: 'flex', gap: 1 }}>
                <TextField size="small" label="方法" value={method} onChange={(event) => setMethod(event.target.value)} sx={{ width: 130 }} />
                <TextField size="small" fullWidth label="路径" value={path} onChange={(event) => setPath(event.target.value)} />
              </Box>
            ) : (
              <TextField
                size="small"
                label="响应状态码"
                value={status}
                onChange={(event) => setStatus(event.target.value)}
                sx={{ width: 160 }}
              />
            )}

            <Box>
              <Typography sx={{ fontSize: 9.5, color: 'text.disabled', mb: 0.4 }}>
                {phase === 'request' ? '请求 Header' : '响应 Header'}（每行 Name: Value，覆盖同名项）
              </Typography>
              <TextField
                size="small"
                fullWidth
                multiline
                minRows={4}
                value={headers}
                onChange={(event) => setHeaders(event.target.value)}
              />
            </Box>

            <Box>
              <Typography sx={{ fontSize: 9.5, color: 'text.disabled', mb: 0.4 }}>
                覆盖正文（留空表示保持原正文）
              </Typography>
              <TextField
                size="small"
                fullWidth
                multiline
                minRows={3}
                value={body}
                onChange={(event) => setBody(event.target.value)}
              />
            </Box>
          </Box>
        )}
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose}>取消</Button>
        <Button
          variant="contained"
          onClick={() => void submit()}
          disabled={busy || !flow}
          startIcon={busy ? <CircularProgress size={12} color="inherit" /> : undefined}
        >
          放行
        </Button>
      </DialogActions>
    </Dialog>
  );
}
