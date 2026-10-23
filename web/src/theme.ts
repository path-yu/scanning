import { alpha, createTheme, type PaletteMode, type Theme } from '@mui/material/styles';

export function createAppTheme(mode: PaletteMode): Theme {
  const dark = mode === 'dark';
  const bg = dark ? '#0a0e13' : '#f4f6f9';
  const paper = dark ? '#101720' : '#ffffff';
  const panel = dark ? '#131b25' : '#ffffff';
  const border = dark ? '#1e2a37' : '#dbe3ec';
  const textPrimary = dark ? '#e6edf3' : '#0f172a';
  const textSecondary = dark ? '#8b97a6' : '#5b6b7c';
  const primary = dark ? '#38bdf8' : '#0369a1';

  return createTheme({
    palette: {
      mode,
      primary: { main: primary },
      secondary: { main: dark ? '#a78bfa' : '#6d28d9' },
      success: { main: '#34d399' },
      warning: { main: '#fbbf24' },
      error: { main: '#f87171' },
      info: { main: '#38bdf8' },
      background: { default: bg, paper },
      divider: border,
      text: { primary: textPrimary, secondary: textSecondary },
    },
    shape: { borderRadius: 8 },
    typography: {
      fontFamily:
        '"Inter", "Segoe UI Variable", "Segoe UI", "PingFang SC", "Microsoft YaHei", system-ui, sans-serif',
      fontSize: 14,
      h6: { fontSize: 15, fontWeight: 650, letterSpacing: '-0.01em' },
      subtitle2: { fontSize: 13, fontWeight: 600 },
      body2: { fontSize: 13.5 },
      caption: { fontSize: 12, letterSpacing: '0.01em' },
      button: { textTransform: 'none', fontWeight: 600, fontSize: 13 },
      overline: { fontSize: 10.5, letterSpacing: '0.08em', fontWeight: 700 },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          'html, body, #root': { height: '100%' },
          body: {
            margin: 0,
            overflow: 'hidden',
            backgroundColor: bg,
            color: textPrimary,
            WebkitFontSmoothing: 'antialiased',
            fontVariantNumeric: 'tabular-nums',
          },
          '*::-webkit-scrollbar': { width: 9, height: 9 },
          '*::-webkit-scrollbar-track': { background: 'transparent' },
          '*::-webkit-scrollbar-thumb': {
            background: dark ? '#263242' : '#c5d0dc',
            borderRadius: 6,
            border: '2px solid transparent',
            backgroundClip: 'padding-box',
          },
          '*::-webkit-scrollbar-thumb:hover': {
            background: dark ? '#334155' : '#aab8c7',
            backgroundClip: 'padding-box',
          },
          '::selection': { background: alpha(primary, 0.28) },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: 'none',
            borderColor: border,
          },
        },
      },
      MuiButton: {
        defaultProps: { disableElevation: true },
        styleOverrides: {
          root: {
            textTransform: 'none',
            borderRadius: 7,
            fontWeight: 600,
            fontSize: 13,
            paddingInline: 12,
          },
          sizeSmall: { height: 30 },
        },
      },
      MuiIconButton: {
        styleOverrides: {
          root: { borderRadius: 7, color: textSecondary },
          sizeSmall: { padding: 5 },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            height: 23,
            fontSize: 11.5,
            fontWeight: 600,
            borderRadius: 6,
            '& .MuiChip-label': { paddingLeft: 7, paddingRight: 7 },
            '& .MuiChip-icon': { fontSize: 13, marginLeft: 6 },
          },
        },
      },
      MuiTooltip: {
        defaultProps: { arrow: true, enterDelay: 450 },
        styleOverrides: {
          tooltip: {
            fontSize: 12,
            padding: '6px 8px',
            borderRadius: 6,
            backgroundColor: dark ? '#1f2937' : '#1e293b',
            color: '#f8fafc',
            border: `1px solid ${dark ? '#334155' : '#334155'}`,
          },
          arrow: { color: dark ? '#1f2937' : '#1e293b' },
        },
      },
      MuiTab: {
        styleOverrides: {
          root: {
            textTransform: 'none',
            minHeight: 40,
            minWidth: 0,
            padding: '0 12px',
            fontSize: 13,
            fontWeight: 600,
            color: textSecondary,
          },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: { height: 2, borderRadius: 2 },
        },
      },
      MuiInputBase: {
        styleOverrides: {
          root: {
            fontSize: 13.5,
            borderRadius: 7,
            backgroundColor: dark ? alpha('#ffffff', 0.025) : alpha('#0f172a', 0.025),
            '&:before, &:after': { display: 'none' },
          },
          input: { padding: '7px 10px' },
        },
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            backgroundColor: dark ? alpha('#ffffff', 0.025) : alpha('#0f172a', 0.02),
            '& .MuiOutlinedInput-notchedOutline': { borderColor: border },
            '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: border },
            '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
              borderColor: primary,
              borderWidth: 1,
            },
          },
        },
      },
      MuiDialog: {
        styleOverrides: {
          paper: {
            backgroundImage: 'none',
            backgroundColor: panel,
            border: `1px solid ${border}`,
            borderRadius: 12,
            boxShadow: dark ? '0 24px 64px rgba(0,0,0,0.55)' : '0 24px 64px rgba(15,23,42,0.18)',
          },
        },
      },
      MuiDivider: {
        styleOverrides: { root: { borderColor: border } },
      },
      MuiSkeleton: {
        styleOverrides: {
          root: { backgroundColor: dark ? alpha('#ffffff', 0.06) : alpha('#0f172a', 0.06) },
        },
      },
      MuiAlert: {
        styleOverrides: {
          root: { fontSize: 13, borderRadius: 8 },
        },
      },
    },
  });
}
