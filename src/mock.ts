/**
 * 浏览器预览用的假后端。
 *
 * 前端跑在 Tauri 里时走真实 `invoke`；用 `vite dev` 打开浏览器时，
 * 没有 Rust 侧，这层就顶上，返回一批假数据。
 *
 * 这样调界面不用重新编译 Rust —— 改一行 CSS 浏览器自动刷新，几百毫秒的事。
 * 判断依据：Tauri 运行时会注入 `window.__TAURI_INTERNALS__`。
 */

export const IN_TAURI = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/**
 * 浏览器预览：默认停在「设置密码」页（`?screen=lock` 可看登录页）。
 * 真实应用里这个键由 Tauri 侧写入，浏览器与它是两套 localStorage。
 */
const now = () => Math.floor(Date.now() / 1000);

interface MockEntry {
  id: string;
  kind: string;
  name: string;
  username: string;
  secret: string;
  url: string;
  tags: string[];
  notes: string;
  fields: { name: string; value: string; secret: boolean }[];
  created_at: number;
  updated_at: number;
  expires_at: number;
  use_count: number;
  last_used_at: number;
}

/* 预置数据为空：浏览器预览从零开始，和真实首次使用一致。 */
const seed: MockEntry[] = [];

let store: MockEntry[] = JSON.parse(JSON.stringify(seed));

function toItem(e: MockEntry) {
  return {
    id: e.id,
    kind: ["login", "api_key", "note", "card", "credential"].indexOf(e.kind),
    name: e.name,
    username: e.username,
    url: e.url,
    tags: e.tags,
    use_count: e.use_count,
    last_used_at: e.last_used_at,
    expires_at: e.expires_at,
    expired: e.expires_at > 0 && e.expires_at <= now(),
  };
}

const wait = (ms = 0) => new Promise((r) => setTimeout(r, ms));

/** 假后端。签名与 api.ts 保持一致，方便直接替换。 */
export const mockApi = {
  uiReady: async () => {},
  status: async () => ({
    unlocked: true,
    path: "C:\\Users\\demo\\AppData\\Roaming\\cn.xuanze.vault\\vault.xzvlt",
    dirty: false,
    count: store.length,
    seconds_until_lock: 300,
  }),
  create: async () => {},
  open: async () => {},
  lock: async () => {},
  save: async () => {},
  defaultVaultPath: async () => "C:\\Users\\demo\\AppData\\Roaming\\cn.xuanze.vault\\vault.xzvlt",
  // 浏览器预览里没有真实库文件：报「已有库」，让预览直接进登录页，
  // 而不是把每次刷新都当成第一次使用、跳到注册页。
  vaultExists: async () => ({
    known: true,
    file_exists: true,
    path: "C:\\Users\\demo\\AppData\\Roaming\\cn.xuanze.vault\\vault.xzvlt",
  }),
  rekey: async () => {},

  hot: async (limit: number) => {
    await wait(4);
    return [...store].sort((a, b) => b.use_count - a.use_count).slice(0, limit).map(toItem);
  },
  all: async () => store.map(toItem),
  search: async (q: string, limit: number) => {
    await wait(4);
    const s = q.toLowerCase();
    return store
      .filter(
        (e) =>
          e.name.toLowerCase().includes(s) ||
          e.username.toLowerCase().includes(s) ||
          e.url.toLowerCase().includes(s) ||
          e.tags.some((t) => t.toLowerCase().includes(s)),
      )
      .slice(0, limit)
      .map(toItem);
  },

  get: async (id: string) => {
    await wait(6);
    const e = store.find((x) => x.id === id);
    if (!e) throw "条目不存在";
    return { ...e, secret_len: e.secret.length };
  },
  reveal: async (id: string, fi?: number) => {
    const e = store.find((x) => x.id === id);
    if (!e) throw "条目不存在";
    return fi === undefined || fi === null ? e.secret : (e.fields[fi]?.value ?? "");
  },
  saveEntry: async (input: Record<string, unknown>) => {
    await wait(10);
    const id = (input.id as string) || String(Date.now());
    const idx = store.findIndex((x) => x.id === id);
    const prev = idx >= 0 ? store[idx] : undefined;
    const rec: MockEntry = {
      id,
      kind: input.kind as string,
      name: input.name as string,
      username: (input.username as string) ?? "",
      secret: (input.secret as string) || prev?.secret || "",
      url: (input.url as string) ?? "",
      notes: (input.notes as string) ?? "",
      tags: (input.tags as string[]) ?? [],
      fields: (input.fields as MockEntry["fields"]) ?? [],
      created_at: prev?.created_at ?? now(),
      updated_at: now(),
      expires_at: (input.expires_at as number) ?? 0,
      use_count: prev?.use_count ?? 0,
      last_used_at: prev?.last_used_at ?? 0,
    };
    if (idx >= 0) store[idx] = rec;
    else store = [rec, ...store];
    return id;
  },
  deleteEntry: async (id: string) => {
    store = store.filter((x) => x.id !== id);
  },
  recordUse: async () => {},

  copy: async (text: string, sensitive: boolean) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      /* 浏览器无权限时忽略 */
    }
    void sensitive;
  },
  copyByHeat: async (i: number) => {
    const e = [...store].sort((a, b) => b.use_count - a.use_count)[i];
    return e?.name ?? "（无）";
  },

  exportBackup: async () => store.length,
  importBackup: async () => ({ imported: 0, skipped: 0, errors: [] }),
  autoUnlockStatus: async () => false,
  enableAutoUnlock: async () => {},
  disableAutoUnlock: async () => {},

  touch: async () => {},
  autolockCheck: async () => ({ locked: false, save_error: null }),
  autolockMinutes: async () => 5,
  setAutolock: async (m: number) => m,
};