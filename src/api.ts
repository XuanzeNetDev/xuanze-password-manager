/**
 * Rust 后端命令的薄封装。
 *
 * 只有一个理由存在这层：让前端代码里不出现裸字符串命令名和裸 `any`。
 * 类型是照着 `src-tauri/src/commands.rs` 手写的，两边改要同步。
 */

import { invoke } from "@tauri-apps/api/core";

export interface VaultStatus {
  unlocked: boolean;
  path: string | null;
  dirty: boolean;
  count: number;
  seconds_until_lock: number | null;
}

export interface VaultStats {
  total: number;
  expired: number;
  never_used: number;
  tags: number;
}

export interface ItemView {
  id: string;
  kind: number;
  name: string;
  username: string;
  url: string;
  tags: string[];
  use_count: number;
  last_used_at: number;
  expires_at: number;
  expired: boolean;
}

export interface HitView extends ItemView {
  score: number;
  field: "name" | "username" | "url" | "tag";
}

export interface FieldView {
  name: string;
  value: string;
  secret: boolean;
}

export interface EntryView {
  id: string;
  kind: string;
  name: string;
  username: string;
  url: string;
  notes: string;
  tags: string[];
  fields: FieldView[];
  created_at: number;
  updated_at: number;
  expires_at: number;
  use_count: number;
  last_used_at: number;
  secret_len: number;
}

export interface EntryInput {
  id?: string;
  kind: string;
  name: string;
  username?: string;
  secret?: string;
  url?: string;
  notes?: string;
  tags?: string[];
  fields?: { name: string; value: string; secret: boolean }[];
  expires_at?: number;
}

/** 条目类型码 → i18n key 后缀。与 `entry::EntryKind::code()` 一一对应。 */
export const KIND_KEYS = ["login", "api_key", "note", "card", "credential"] as const;

export function kindKey(code: number): string {
  return KIND_KEYS[code] ?? "api_key";
}

export const api = {
  status: () => invoke<VaultStatus>("vault_status"),
  /** 通知后端：首屏已绘制，可以显示窗口了。 */
  uiReady: () => invoke<void>("ui_ready"),
  create: (password: string, level?: string) =>
    invoke<void>("vault_create", { password, level }),
  open: (path: string, password: string) =>
    invoke<void>("vault_open", { path, password }),
  close: () => invoke<void>("vault_close"),
  lock: () => invoke<void>("vault_lock"),
  save: (path?: string) => invoke<void>("vault_save", { path: path ?? null }),
  defaultVaultPath: () => invoke<string>("default_vault_path"),
  rekey: (oldPassword: string, newPassword: string, path: string) =>
    invoke<void>("vault_rekey", { oldPassword, newPassword, path }),
  stats: () => invoke<VaultStats>("vault_stats"),

  hot: (limit: number) => invoke<ItemView[]>("list_hot", { limit }),
  all: () => invoke<ItemView[]>("list_all"),
  search: (query: string, limit?: number) =>
    invoke<HitView[]>("search_entries", { query, limit: limit ?? 50 }),
  tags: () => invoke<[string, number][]>("list_tags"),

  get: (id: string) => invoke<EntryView>("entry_get", { id }),
  reveal: (id: string, fieldIndex?: number) =>
    invoke<string>("entry_reveal", { id, fieldIndex: fieldIndex ?? null }),
  saveEntry: (input: EntryInput) => invoke<string>("entry_save", { input }),
  deleteEntry: (id: string) => invoke<void>("entry_delete", { id }),
  recordUse: (id: string) => invoke<void>("entry_record_use", { id }),

  copy: (text: string, sensitive: boolean) =>
    invoke<void>("copy_to_clipboard", { text, sensitive }),
  copyByHeat: (index: number) => invoke<string>("copy_secret_by_heat", { index }),

  touch: () => invoke<void>("touch_activity"),
  autolockCheck: () => invoke<boolean>("autolock_check"),
  exportCsv: (path: string) => invoke<number>("export_csv", { path }),
  exportXlsx: (path: string) => invoke<number>("export_xlsx", { path }),
};

/** 把后端抛出的错误转成一句人话。 */
export function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}