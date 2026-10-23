import { useEffect, useState } from 'react';
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
  Snackbar,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import dayjs from 'dayjs';
import { Close, DeleteOutline, Refresh, SaveOutlined, FolderOpenOutlined } from '@mui/icons-material';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { formatDateTime, formatNumber } from '@/lib/format';
import type { SavedSession } from '@/types';

interface SessionDialogProps {
  open: boolean;
  currentName?: string;
  onClose: () => void;
  onLoaded: () => Promise<void> | void;
}

export function SessionDialog({ open, currentName, onClose, onLoaded }: SessionDialogProps) {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [busy, setBusy] = useState<'save' | 'load' | 'delete' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [snack, setSnack] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<SavedSession | null>(null);

  const sessionsQuery = useQuery({
    queryKey: ['sessions'],
    queryFn: api.listSessions,
    enabled: open,
  });

  useEffect(() => {
    if (!open) return;
    setError(null);
    setName(`${currentName ?? '默认会话'} · ${dayjs().format('MM-DD HH:mm')}`);
  }, [open, currentName]);

  const sessions = sessionsQuery.data?.sessions ?? [];

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['sessions'] });
  };

  const save = async () => {
    if (!name.trim()) {
      setError('会话名称不能为空');
      return;
    }
    setBusy('save');
    setError(null);
    try {
      const saved = await api.saveSession(name.trim());
      setSnack(`已保存 ${saved.flowCount} 条流量`);
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const load = async (session: SavedSession) => {
    setBusy('load');
    setError(null);
    try {
      const result = await api.loadSession(session.id);
      setSnack(`已加载 ${formatNumber(result.count)} 条流量`);
      await onLoaded();
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  const remove = async () => {
    if (!deleting) return;
    setBusy('delete');
    setError(null);
    try {
      await api.deleteSession(deleting.id);
      setDeleting(null);
      setSnack('已删除保存的会话');
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pr: 1 }}>
          <Box sx={{ flex: 1, fontSize: 15, fontWeight: 700 }}>会话存档</Box>
          <Tooltip title="刷新">
            <IconButton size="small" onClick={() => void sessionsQuery.refetch()} disabled={sessionsQuery.isFetching}>
              <Refresh sx={{ fontSize: 15 }} />
            </IconButton>
          </Tooltip>
          <IconButton size="small" onClick={onClose} aria-label="关闭">
            <Close sx={{ fontSize: 16 }} />
          </IconButton>
        </DialogTitle>

        <DialogContent sx={{ pt: 0.5, pb: 1 }}>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
            {error ? <Alert severity="error">{error}</Alert> : null}

            <Box
              sx={{
                p: 1.5,
                border: '1px solid',
                borderColor: 'divider',
                borderRadius: 1.5,
                bgcolor: 'action.hover',
              }}
            >
              <Typography sx={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: 'text.disabled', mb: 0.75 }}>
                保存当前会话
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                <TextField
                  size="small"
                  fullWidth
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="会话名称"
                />
                <Button
                  size="small"
                  variant="contained"
                  startIcon={busy === 'save' ? <CircularProgress size={12} color="inherit" /> : <SaveOutlined sx={{ fontSize: 14 }} />}
                  onClick={() => void save()}
                  disabled={busy !== null}
                  sx={{ flexShrink: 0 }}
                >
                  保存
                </Button>
              </Box>
              <Typography sx={{ fontSize: 10.5, color: 'text.disabled', mt: 0.75 }}>
                保存会把当前内存中的 Flow 与完整正文写入 SQLite，重启后仍可加载。
              </Typography>
            </Box>

            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography sx={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: 'text.disabled' }}>
                已保存会话
              </Typography>
              <Chip size="small" label={formatNumber(sessions.length)} variant="outlined" />
              <Box sx={{ flex: 1 }} />
              <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>加载会替换当前流量列表</Typography>
            </Box>

            {sessionsQuery.isLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
                <CircularProgress size={18} />
              </Box>
            ) : sessions.length === 0 ? (
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
                还没有保存的会话。
              </Box>
            ) : (
              <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, overflow: 'hidden' }}>
                {sessions.map((session, index) => (
                  <Box
                    key={session.id}
                    sx={{
                      display: 'grid',
                      gridTemplateColumns: '1fr auto',
                      gap: 1,
                      alignItems: 'center',
                      px: 1.25,
                      py: 1,
                      borderTop: index === 0 ? 'none' : '1px solid',
                      borderColor: 'divider',
                    }}
                  >
                    <Box sx={{ minWidth: 0 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, flexWrap: 'wrap' }}>
                        <Typography sx={{ fontSize: 12, fontWeight: 650 }}>{session.name}</Typography>
                        <Chip size="small" label={`${formatNumber(session.flowCount)} 条`} variant="outlined" />
                      </Box>
                      <Typography className="mono" sx={{ fontSize: 10, color: 'text.disabled', mt: 0.35 }}>
                        保存于 {formatDateTime(session.savedAt)} · {session.id.slice(-8)}
                      </Typography>
                    </Box>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={
                          busy === 'load' ? (
                            <CircularProgress size={12} color="inherit" />
                          ) : (
                            <FolderOpenOutlined sx={{ fontSize: 14 }} />
                          )
                        }
                        onClick={() => void load(session)}
                        disabled={busy !== null}
                      >
                        加载
                      </Button>
                      <Tooltip title="删除会话">
                        <IconButton size="small" onClick={() => setDeleting(session)} disabled={busy !== null}>
                          <DeleteOutline sx={{ fontSize: 15 }} />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </Box>
                ))}
              </Box>
            )}
          </Box>
        </DialogContent>

        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={onClose}>关闭</Button>
        </DialogActions>
      </Dialog>

      <ConfirmDialog
        open={Boolean(deleting)}
        title="删除已保存的会话？"
        description={deleting ? `会话「${deleting.name}」的流量索引将从 SQLite 中删除，正文缓存可能仍保留在数据目录。` : ''}
        confirmLabel="删除"
        onCancel={() => setDeleting(null)}
        onConfirm={() => void remove()}
      />

      <Snackbar
        open={Boolean(snack)}
        autoHideDuration={2000}
        onClose={() => setSnack(null)}
        message={snack}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      />
    </>
  );
}

function messageOf(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  return '操作失败';
}
