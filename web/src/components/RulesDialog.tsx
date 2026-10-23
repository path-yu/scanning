import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControlLabel,
  IconButton,
  MenuItem,
  Snackbar,
  Switch,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import { Add, ArrowBack, DeleteOutline, EditOutlined, Close } from '@mui/icons-material';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import {
  actionLabel,
  headersToText,
  matchSummary,
  methodsToText,
  ruleSummary,
  textToHeaders,
  textToMethods,
} from '@/lib/rules';
import type { Rule, RuleAction, RuleActionType, RulePhase } from '@/types';

interface RulesDialogProps {
  open: boolean;
  onClose: () => void;
}

interface ActionDraft {
  type: RuleActionType;
  status: string;
  headers: string;
  removeHeaders: string;
  body: string;
  overrideBody: boolean;
  delayMs: string;
  remote: string;
  method: string;
  path: string;
}

interface RuleDraft {
  id: string;
  name: string;
  enabled: boolean;
  priority: string;
  phase: RulePhase;
  stop: boolean;
  methods: string;
  host: string;
  path: string;
  status: string;
  mime: string;
  headerName: string;
  headerValue: string;
  bodyContains: string;
  actions: ActionDraft[];
}

const ACTION_TYPES: { value: RuleActionType; label: string }[] = [
  { value: 'mock', label: '返回 Mock 响应' },
  { value: 'block', label: '阻断请求' },
  { value: 'delay', label: '延迟' },
  { value: 'map_remote', label: '转发到其他目标' },
  { value: 'rewrite_request', label: '改写请求' },
  { value: 'rewrite_response', label: '改写响应' },
  { value: 'pause', label: '断点暂停' },
];

function emptyAction(type: RuleActionType = 'mock'): ActionDraft {
  return {
    type,
    status: type === 'block' ? '403' : type === 'mock' ? '200' : '',
    headers: '',
    removeHeaders: '',
    body: type === 'mock' ? '{}' : '',
    overrideBody: type === 'mock',
    delayMs: type === 'delay' ? '500' : '',
    remote: '',
    method: '',
    path: '',
  };
}

function emptyDraft(): RuleDraft {
  return {
    id: '',
    name: '新规则',
    enabled: true,
    priority: '100',
    phase: 'request',
    stop: false,
    methods: '',
    host: '',
    path: '',
    status: '',
    mime: '',
    headerName: '',
    headerValue: '',
    bodyContains: '',
    actions: [emptyAction()],
  };
}

function draftFromRule(rule: Rule): RuleDraft {
  return {
    id: rule.id,
    name: rule.name,
    enabled: rule.enabled,
    priority: String(rule.priority ?? 100),
    phase: rule.phase,
    stop: rule.stop,
    methods: methodsToText(rule.match.methods),
    host: rule.match.host ?? '',
    path: rule.match.path ?? '',
    status: rule.match.status ?? '',
    mime: rule.match.mime ?? '',
    headerName: rule.match.headerName ?? '',
    headerValue: rule.match.headerValue ?? '',
    bodyContains: rule.match.bodyContains ?? '',
    actions: (rule.actions ?? []).map((action) => ({
      type: action.type,
      status: action.status ? String(action.status) : '',
      headers: headersToText(action.headers),
      removeHeaders: (action.removeHeaders ?? []).join(', '),
      body: action.body ?? '',
      overrideBody: action.body !== undefined,
      delayMs: action.delayMs ? String(action.delayMs) : '',
      remote: action.remote ?? '',
      method: action.method ?? '',
      path: action.path ?? '',
    })),
  };
}

function draftToRule(draft: RuleDraft): Rule {
  return {
    id: draft.id,
    name: draft.name.trim(),
    enabled: draft.enabled,
    priority: Number(draft.priority) || 0,
    phase: draft.phase,
    stop: draft.stop,
    match: {
      methods: textToMethods(draft.methods),
      host: draft.host.trim(),
      path: draft.path.trim(),
      status: draft.status.trim(),
      mime: draft.mime.trim(),
      headerName: draft.headerName.trim(),
      headerValue: draft.headerValue.trim(),
      bodyContains: draft.bodyContains,
    },
    actions: draft.actions.map((action): RuleAction => {
      switch (action.type) {
        case 'mock':
        case 'block':
          return {
            type: action.type,
            status: Number(action.status) || (action.type === 'block' ? 403 : 200),
            headers: textToHeaders(action.headers),
            body: action.overrideBody ? action.body : undefined,
          };
        case 'delay':
          return { type: action.type, delayMs: Number(action.delayMs) || 0 };
        case 'map_remote':
          return { type: action.type, remote: action.remote.trim() };
        case 'rewrite_request':
          return {
            type: action.type,
            method: action.method.trim().toUpperCase(),
            path: action.path.trim(),
            headers: textToHeaders(action.headers),
            body: action.overrideBody ? action.body : undefined,
          };
        case 'rewrite_response':
          return {
            type: action.type,
            status: Number(action.status) || undefined,
            headers: textToHeaders(action.headers),
            removeHeaders: action.removeHeaders
              .split(',')
              .map((item) => item.trim())
              .filter(Boolean),
            body: action.overrideBody ? action.body : undefined,
          };
        default:
          return { type: action.type };
      }
    }),
  };
}

export function RulesDialog({ open, onClose }: RulesDialogProps) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<RuleDraft | null>(null);
  const [deleting, setDeleting] = useState<Rule | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [snack, setSnack] = useState<string | null>(null);

  const rulesQuery = useQuery({
    queryKey: ['rules'],
    queryFn: api.listRules,
    enabled: open,
  });

  useEffect(() => {
    if (!open) {
      setEditing(null);
      setError(null);
    }
  }, [open]);

  const rules = rulesQuery.data ?? [];

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['rules'] });
  };

  const toggleRule = async (rule: Rule, enabled: boolean) => {
    setError(null);
    try {
      await api.updateRule(rule.id, { ...rule, enabled });
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    }
  };

  const save = async () => {
    if (!editing) return;
    const payload = draftToRule(editing);
    if (!payload.name) {
      setError('规则名称不能为空');
      return;
    }
    if (!payload.actions.length) {
      setError('至少需要一个动作');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (editing.id) {
        await api.updateRule(editing.id, payload);
      } else {
        const { id: _id, ...rest } = payload;
        void _id;
        await api.createRule(rest);
      }
      setSnack('规则已保存');
      setEditing(null);
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!deleting) return;
    setBusy(true);
    setError(null);
    try {
      await api.deleteRule(deleting.id);
      setDeleting(null);
      setSnack('规则已删除');
      await refresh();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pr: 1 }}>
          {editing ? (
            <IconButton size="small" onClick={() => setEditing(null)} aria-label="返回">
              <ArrowBack sx={{ fontSize: 16 }} />
            </IconButton>
          ) : null}
          <Box sx={{ flex: 1, fontSize: 15, fontWeight: 700 }}>
            {editing ? (editing.id ? '编辑规则' : '新建规则') : '规则引擎'}
          </Box>
          {!editing ? (
            <Button size="small" variant="contained" startIcon={<Add sx={{ fontSize: 15 }} />} onClick={() => setEditing(emptyDraft())}>
              新建规则
            </Button>
          ) : null}
          <IconButton size="small" onClick={onClose} aria-label="关闭">
            <Close sx={{ fontSize: 16 }} />
          </IconButton>
        </DialogTitle>

        <DialogContent sx={{ pt: 0.5, pb: 1 }}>
          {error ? <Alert severity="error" sx={{ mb: 1.25 }}>{error}</Alert> : null}

          {editing ? (
            <RuleEditor draft={editing} onChange={setEditing} />
          ) : (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.25 }}>
              <Alert severity="info" variant="outlined" sx={{ py: 0.25 }}>
                规则按优先级数值从小到大执行；命中的规则会显示在流量详情中。请求阶段与响应阶段分别匹配。
              </Alert>

              {rulesQuery.isLoading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
                  <CircularProgress size={18} />
                </Box>
              ) : rules.length === 0 ? (
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
                  还没有规则。新建一条规则即可 Mock 响应、阻断请求或设置断点。
                </Box>
              ) : (
                rules.map((rule) => (
                  <Box
                    key={rule.id}
                    sx={{
                      border: '1px solid',
                      borderColor: 'divider',
                      borderRadius: 1.25,
                      p: 1.25,
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: 1,
                      opacity: rule.enabled ? 1 : 0.6,
                    }}
                  >
                    <Switch
                      size="small"
                      checked={rule.enabled}
                      onChange={(event) => void toggleRule(rule, event.target.checked)}
                    />
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, flexWrap: 'wrap' }}>
                        <Typography sx={{ fontSize: 12.5, fontWeight: 650 }}>{rule.name}</Typography>
                        <Chip size="small" label={rule.phase === 'request' ? '请求' : '响应'} variant="outlined" />
                        <Chip size="small" label={`P${rule.priority}`} variant="outlined" />
                        {rule.stop ? <Chip size="small" label="停止匹配" variant="outlined" /> : null}
                      </Box>
                      <Typography className="mono" sx={{ fontSize: 10.5, color: 'text.disabled', mt: 0.4 }}>
                        {matchSummary(rule.match)}
                      </Typography>
                      <Typography sx={{ fontSize: 10.5, color: 'text.secondary', mt: 0.3 }}>
                        {ruleSummary(rule)}
                      </Typography>
                    </Box>
                    <Tooltip title="编辑">
                      <IconButton size="small" onClick={() => setEditing(draftFromRule(rule))}>
                        <EditOutlined sx={{ fontSize: 15 }} />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="删除">
                      <IconButton size="small" onClick={() => setDeleting(rule)}>
                        <DeleteOutline sx={{ fontSize: 15 }} />
                      </IconButton>
                    </Tooltip>
                  </Box>
                ))
              )}
            </Box>
          )}
        </DialogContent>

        <DialogActions sx={{ px: 3, pb: 2 }}>
          {editing ? (
            <>
              <Button onClick={() => setEditing(null)}>取消</Button>
              <Button
                variant="contained"
                onClick={() => void save()}
                disabled={busy}
                startIcon={busy ? <CircularProgress size={12} color="inherit" /> : undefined}
              >
                保存规则
              </Button>
            </>
          ) : (
            <Button onClick={onClose}>关闭</Button>
          )}
        </DialogActions>
      </Dialog>

      <ConfirmDialog
        open={Boolean(deleting)}
        title="删除规则？"
        description={deleting ? `规则「${deleting.name}」删除后不再参与匹配，且无法恢复。` : ''}
        confirmLabel="删除"
        onCancel={() => setDeleting(null)}
        onConfirm={() => void remove()}
      />

      <Snackbar
        open={Boolean(snack)}
        autoHideDuration={1600}
        onClose={() => setSnack(null)}
        message={snack}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      />
    </>
  );
}

function RuleEditor({ draft, onChange }: { draft: RuleDraft; onChange: (next: RuleDraft) => void }) {
  const patch = (partial: Partial<RuleDraft>) => onChange({ ...draft, ...partial });
  const patchAction = (index: number, partial: Partial<ActionDraft>) => {
    const actions = draft.actions.map((action, i) => (i === index ? { ...action, ...partial } : action));
    onChange({ ...draft, actions });
  };

  const actions = useMemo(() => draft.actions, [draft.actions]);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
      <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 110px 120px', gap: 1 }}>
        <Field label="名称">
          <TextField size="small" fullWidth value={draft.name} onChange={(event) => patch({ name: event.target.value })} />
        </Field>
        <Field label="优先级">
          <TextField
            size="small"
            fullWidth
            type="number"
            value={draft.priority}
            onChange={(event) => patch({ priority: event.target.value })}
          />
        </Field>
        <Field label="阶段">
          <TextField
            size="small"
            fullWidth
            select
            value={draft.phase}
            onChange={(event) => patch({ phase: event.target.value as RulePhase })}
          >
            <MenuItem value="request">请求</MenuItem>
            <MenuItem value="response">响应</MenuItem>
          </TextField>
        </Field>
      </Box>

      <Box sx={{ display: 'flex', gap: 2 }}>
        <FormControlLabel
          control={<Switch size="small" checked={draft.enabled} onChange={(event) => patch({ enabled: event.target.checked })} />}
          label={<Typography sx={{ fontSize: 11.5 }}>启用</Typography>}
        />
        <FormControlLabel
          control={<Switch size="small" checked={draft.stop} onChange={(event) => patch({ stop: event.target.checked })} />}
          label={<Typography sx={{ fontSize: 11.5 }}>命中后停止后续规则</Typography>}
        />
      </Box>

      <Divider />
      <Typography sx={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: 'text.disabled' }}>
        匹配条件（留空表示不限）
      </Typography>

      <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>
        <Field label="方法（逗号分隔）">
          <TextField
            size="small"
            fullWidth
            placeholder="GET, POST"
            value={draft.methods}
            onChange={(event) => patch({ methods: event.target.value })}
          />
        </Field>
        <Field label="主机（支持 * 通配）">
          <TextField
            size="small"
            fullWidth
            placeholder="api.example.com 或 *.example.com"
            value={draft.host}
            onChange={(event) => patch({ host: event.target.value })}
          />
        </Field>
        <Field label="路径（支持 * 通配）">
          <TextField
            size="small"
            fullWidth
            placeholder="/api/*"
            value={draft.path}
            onChange={(event) => patch({ path: event.target.value })}
          />
        </Field>
        <Field label="状态码（响应阶段）">
          <TextField
            size="small"
            fullWidth
            placeholder="200, 4xx"
            value={draft.status}
            onChange={(event) => patch({ status: event.target.value })}
          />
        </Field>
        <Field label="MIME（响应阶段）">
          <TextField
            size="small"
            fullWidth
            placeholder="application/json"
            value={draft.mime}
            onChange={(event) => patch({ mime: event.target.value })}
          />
        </Field>
        <Field label="正文包含（请求阶段）">
          <TextField
            size="small"
            fullWidth
            value={draft.bodyContains}
            onChange={(event) => patch({ bodyContains: event.target.value })}
          />
        </Field>
        <Field label="Header 名称">
          <TextField
            size="small"
            fullWidth
            value={draft.headerName}
            onChange={(event) => patch({ headerName: event.target.value })}
          />
        </Field>
        <Field label="Header 值包含">
          <TextField
            size="small"
            fullWidth
            value={draft.headerValue}
            onChange={(event) => patch({ headerValue: event.target.value })}
          />
        </Field>
      </Box>

      <Divider />
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Typography sx={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: 'text.disabled' }}>
          动作
        </Typography>
        <Box sx={{ flex: 1 }} />
        <Button
          size="small"
          startIcon={<Add sx={{ fontSize: 14 }} />}
          onClick={() => onChange({ ...draft, actions: [...draft.actions, emptyAction()] })}
        >
          添加动作
        </Button>
      </Box>

      {actions.map((action, index) => (
        <ActionEditor
          key={index}
          action={action}
          onChange={(partial) => patchAction(index, partial)}
          onRemove={actions.length > 1 ? () => onChange({ ...draft, actions: actions.filter((_, i) => i !== index) }) : undefined}
        />
      ))}
    </Box>
  );
}

function ActionEditor({
  action,
  onChange,
  onRemove,
}: {
  action: ActionDraft;
  onChange: (partial: Partial<ActionDraft>) => void;
  onRemove?: () => void;
}) {
  return (
    <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1.25, display: 'flex', flexDirection: 'column', gap: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <TextField
          size="small"
          select
          label="动作类型"
          value={action.type}
          onChange={(event) => {
            const type = event.target.value as RuleActionType;
            onChange({ ...emptyAction(type), headers: action.headers, body: action.body, overrideBody: action.overrideBody });
          }}
          sx={{ width: 200 }}
        >
          {ACTION_TYPES.map((item) => (
            <MenuItem key={item.value} value={item.value}>
              {item.label}
            </MenuItem>
          ))}
        </TextField>
        <Typography sx={{ fontSize: 10.5, color: 'text.disabled' }}>{actionLabel({ type: action.type })}</Typography>
        <Box sx={{ flex: 1 }} />
        {onRemove ? (
          <Tooltip title="移除动作">
            <IconButton size="small" onClick={onRemove}>
              <DeleteOutline sx={{ fontSize: 15 }} />
            </IconButton>
          </Tooltip>
        ) : null}
      </Box>

      {(action.type === 'mock' || action.type === 'block') ? (
        <Box sx={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: 1 }}>
          <Field label="状态码">
            <TextField size="small" fullWidth type="number" value={action.status} onChange={(event) => onChange({ status: event.target.value })} />
          </Field>
          <Field label="响应 Header（每行 Name: Value）">
            <TextField
              size="small"
              fullWidth
              multiline
              minRows={2}
              value={action.headers}
              onChange={(event) => onChange({ headers: event.target.value })}
            />
          </Field>
          <Box sx={{ gridColumn: '1 / -1' }}>
            <BodyField
              label="响应正文"
              value={action.body}
              override={action.overrideBody}
              onOverride={(value) => onChange({ overrideBody: value })}
              onChange={(value) => onChange({ body: value })}
            />
          </Box>
        </Box>
      ) : null}

      {action.type === 'delay' ? (
        <Field label="延迟（毫秒，最长 60000）">
          <TextField size="small" type="number" value={action.delayMs} onChange={(event) => onChange({ delayMs: event.target.value })} sx={{ width: 160 }} />
        </Field>
      ) : null}

      {action.type === 'map_remote' ? (
        <Field label="目标地址">
          <TextField
            size="small"
            fullWidth
            placeholder="127.0.0.1:8080 或 http://localhost:8080"
            value={action.remote}
            onChange={(event) => onChange({ remote: event.target.value })}
          />
        </Field>
      ) : null}

      {action.type === 'rewrite_request' ? (
        <Box sx={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: 1 }}>
          <Field label="方法">
            <TextField size="small" fullWidth value={action.method} onChange={(event) => onChange({ method: event.target.value })} />
          </Field>
          <Field label="路径">
            <TextField size="small" fullWidth value={action.path} onChange={(event) => onChange({ path: event.target.value })} />
          </Field>
          <Box sx={{ gridColumn: '1 / -1' }}>
            <Field label="Header（每行 Name: Value）">
              <TextField size="small" fullWidth multiline minRows={2} value={action.headers} onChange={(event) => onChange({ headers: event.target.value })} />
            </Field>
          </Box>
          <Box sx={{ gridColumn: '1 / -1' }}>
            <BodyField
              label="请求正文"
              value={action.body}
              override={action.overrideBody}
              onOverride={(value) => onChange({ overrideBody: value })}
              onChange={(value) => onChange({ body: value })}
            />
          </Box>
        </Box>
      ) : null}

      {action.type === 'rewrite_response' ? (
        <Box sx={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: 1 }}>
          <Field label="状态码">
            <TextField size="small" fullWidth type="number" value={action.status} onChange={(event) => onChange({ status: event.target.value })} />
          </Field>
          <Field label="移除 Header（逗号分隔）">
            <TextField size="small" fullWidth value={action.removeHeaders} onChange={(event) => onChange({ removeHeaders: event.target.value })} />
          </Field>
          <Box sx={{ gridColumn: '1 / -1' }}>
            <Field label="Header（每行 Name: Value）">
              <TextField size="small" fullWidth multiline minRows={2} value={action.headers} onChange={(event) => onChange({ headers: event.target.value })} />
            </Field>
          </Box>
          <Box sx={{ gridColumn: '1 / -1' }}>
            <BodyField
              label="响应正文"
              value={action.body}
              override={action.overrideBody}
              onOverride={(value) => onChange({ overrideBody: value })}
              onChange={(value) => onChange({ body: value })}
            />
          </Box>
        </Box>
      ) : null}

      {action.type === 'pause' ? (
        <Alert severity="info" variant="outlined" sx={{ py: 0.25 }}>
          命中后 Flow 会进入暂停状态，可在底部断点横幅或详情面板中放行、改写或中止；超时后自动放行。
        </Alert>
      ) : null}
    </Box>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 9.5, color: 'text.disabled', mb: 0.4 }}>{label}</Typography>
      {children}
    </Box>
  );
}

function BodyField({
  label,
  value,
  override,
  onChange,
  onOverride,
}: {
  label: string;
  value: string;
  override: boolean;
  onChange: (value: string) => void;
  onOverride: (value: boolean) => void;
}) {
  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.3 }}>
        <Typography sx={{ fontSize: 9.5, color: 'text.disabled' }}>{label}</Typography>
        <Box sx={{ flex: 1 }} />
        <FormControlLabel
          control={<Checkbox size="small" checked={override} onChange={(event) => onOverride(event.target.checked)} />}
          label={<Typography sx={{ fontSize: 10.5 }}>覆盖正文</Typography>}
          sx={{ m: 0 }}
        />
      </Box>
      <TextField
        size="small"
        fullWidth
        multiline
        minRows={3}
        value={value}
        placeholder={override ? '' : '不覆盖，保留原始正文'}
        disabled={!override}
        onChange={(event) => onChange(event.target.value)}
      />
    </Box>
  );
}

function messageOf(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  return '操作失败';
}
