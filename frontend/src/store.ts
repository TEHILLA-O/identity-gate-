import { create } from "zustand";

export const WORKSPACES = [
  ["overview", "Overview"],
  ["graph", "Identity Graph"],
  ["directory", "Directory"],
  ["lifecycle", "Lifecycle"],
  ["provisioning", "Provisioning"],
  ["reviews", "Access Reviews"],
  ["policies", "Policies"],
  ["security", "Security"],
  ["audit", "Audit"],
  ["reports", "Reports"],
] as const;

export type Workspace = (typeof WORKSPACES)[number][0];

type Inspector = { title: string; body: unknown } | null;

type Store = {
  workspace: Workspace;
  inspector: Inspector;
  density: boolean;
  palette: boolean;
  focus: string;
  setWorkspace: (workspace: Workspace) => void;
  inspect: (inspector: Inspector) => void;
  toggleDensity: () => void;
  setPalette: (palette: boolean) => void;
  setFocus: (focus: string) => void;
};

export const useUi = create<Store>((set) => ({
  workspace: "overview",
  inspector: null,
  density: false,
  palette: false,
  focus: "",
  setWorkspace: (workspace) => set({ workspace }),
  inspect: (inspector) => set({ inspector }),
  toggleDensity: () => set((state) => ({ density: !state.density })),
  setPalette: (palette) => set({ palette }),
  setFocus: (focus) => set({ focus, workspace: "graph" }),
}));
