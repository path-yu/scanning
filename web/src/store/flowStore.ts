import { create } from 'zustand';
import type { FlowSummary, Stats } from '@/types';

const MAX_FLOWS = 50_000;

interface FlowStore {
  byId: Map<string, FlowSummary>;
  order: string[];
  selectedId: string | null;
  filter: string;
  stats: Stats | null;
  setAll: (flows: FlowSummary[]) => void;
  add: (flows: FlowSummary[]) => void;
  update: (flow: FlowSummary) => void;
  remove: (ids: string[]) => void;
  removeAll: () => void;
  select: (id: string | null) => void;
  setFilter: (value: string) => void;
  setStats: (stats: Stats) => void;
}

export const useFlowStore = create<FlowStore>((set) => ({
  byId: new Map(),
  order: [],
  selectedId: null,
  filter: '',
  stats: null,

  setAll: (flows) =>
    set(() => {
      // 最新请求排在最前面。
      const sorted = [...flows].sort((a, b) => b.seq - a.seq).slice(0, MAX_FLOWS);
      const byId = new Map<string, FlowSummary>();
      const order: string[] = [];
      for (const flow of sorted) {
        byId.set(flow.id, flow);
        order.push(flow.id);
      }
      return { byId, order, selectedId: null };
    }),

  add: (flows) =>
    set((state) => {
      if (!flows.length) return state;
      const byId = new Map(state.byId);
      const fresh: FlowSummary[] = [];
      for (const flow of flows) {
        if (!byId.has(flow.id)) {
          fresh.push(flow);
        }
        byId.set(flow.id, flow);
      }
      if (!fresh.length) {
        return { byId };
      }
      // 同一批新 Flow 按 seq 倒序插到最前面，保证最新请求在顶部。
      fresh.sort((a, b) => b.seq - a.seq);
      const order = [...fresh.map((flow) => flow.id), ...state.order];
      while (order.length > MAX_FLOWS) {
        const removed = order.pop();
        if (removed) byId.delete(removed);
      }
      return { byId, order };
    }),

  update: (flow) =>
    set((state) => {
      if (!state.byId.has(flow.id)) return state;
      const byId = new Map(state.byId);
      byId.set(flow.id, flow);
      return { byId };
    }),

  remove: (ids) =>
    set((state) => {
      if (!ids.length) return state;
      const drop = new Set(ids);
      const byId = new Map(state.byId);
      const order = state.order.filter((id) => {
        if (!drop.has(id)) return true;
        byId.delete(id);
        return false;
      });
      return {
        byId,
        order,
        selectedId: state.selectedId && drop.has(state.selectedId) ? null : state.selectedId,
      };
    }),

  removeAll: () => set({ byId: new Map(), order: [], selectedId: null }),
  select: (id) => set({ selectedId: id }),
  setFilter: (value) => set({ filter: value }),
  setStats: (stats) => set({ stats }),
}));
