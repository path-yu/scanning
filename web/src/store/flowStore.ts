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
      const sorted = [...flows].sort((a, b) => a.seq - b.seq).slice(-MAX_FLOWS);
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
      const order = [...state.order];
      for (const flow of flows) {
        if (!byId.has(flow.id)) {
          order.push(flow.id);
        }
        byId.set(flow.id, flow);
      }
      while (order.length > MAX_FLOWS) {
        const removed = order.shift();
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

  removeAll: () => set({ byId: new Map(), order: [], selectedId: null }),
  select: (id) => set({ selectedId: id }),
  setFilter: (value) => set({ filter: value }),
  setStats: (stats) => set({ stats }),
}));
