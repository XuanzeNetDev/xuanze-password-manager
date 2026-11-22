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

/**
 * 本机是否已经有库。
 *
 * 判据必须来自后端：`localStorage` 只要被清一次（清缓存、换 WebView 版本、
 * 甚至某些系统清理工具），前端就会以为「这是第一次用」，把老用户带进
 * 注册页，在默认路径上建新库并覆盖掉原来那个。
 */
export interface VaultPresence {
  /** 本机登记表里有没有建过库。 */
  known: boolean;
  /** 默认路径上现在有没有库文件。 */
  file_exists: boolean;
  /** 默认路径本身。 */
  path: string;
}

export interface VaultStats {
  total: number;
  expired: number;
  never_used: number;
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
  /**
   * 打开库。
   *
   * 不传路径：库文件位置由后端决定（固定默认位置）。
   * 前端以前要记住路径再传回来，而那个「记住」的地方是可被清空的
   * localStorage —— 判据不该建立在这种状态上。
   */
  open: (password: string) => invoke<void>("vault_open", { password }),
  lock: () => invoke<void>("vault_lock"),
  /** 保存到后端决定的默认位置。同样不接受路径。 */
  save: () => invoke<void>("vault_save"),
  defaultVaultPath: () => invoke<string>("default_vault_path"),
  /** 本机是否已经有库（问后端，不看 localStorage）。 */
  vaultExists: () => invoke<VaultPresence>("vault_exists"),
  rekey: (oldPassword: string, newPassword: string) =>
    invoke<void>("vault_rekey", { oldPassword, newPassword }),

  hot: (limit: number) => invoke<ItemView[]>("list_hot", { limit }),
  all: () => invoke<ItemView[]>("list_all"),
  search: (query: string, limit?: number) =>
    invoke<HitView[]>("search_entries", { query, limit: limit ?? 50 }),

  get: (id: string) => invoke<EntryView>("entry_get", { id }),
  reveal: (id: string, fieldIndex?: number) =>
    invoke<string>("entry_reveal", { id, fieldIndex: fieldIndex ?? null }),
  saveEntry: (input: EntryInput) => invoke<string>("entry_save", { input }),
  deleteEntry: (id: string) => invoke<void>("entry_delete", { id }),
  recordUse: (id: string) => invoke<void>("entry_record_use", { id }),

  copy: (text: string, sensitive: boolean) =>
    invoke<void>("copy_to_clipboard", { text, sensitive }),
  copyByHeat: (index: number) => invoke<string>("copy_secret_by_heat", { index }),
  /** 免密码模式是否已开启。 */
  autoUnlockStatus: () => invoke<boolean>("auto_unlock_status"),
  /** 开启免密码模式（需主密码）。 */
  enableAutoUnlock: (password: string) =>
    invoke<void>("enable_auto_unlock", { password }),
  /** 关闭免密码模式（需主密码）。 */
  disableAutoUnlock: (password: string) =>
    invoke<void>("disable_auto_unlock", { password }),
  /**
   * 导出加密备份（`.xzbak`）。
   *
   * 里面是完整的 xlsx，但外面用 Argon2id + AES-256-GCM 包了一层：
   * 磁盘上不会出现明文表格。`backupPassword` 是这个文件的锁，不能为空。
   */
  exportBackup: (path: string, password: string, backupPassword: string) =>
    invoke<number>("export_backup", { path, password, backupPassword }),
  /**
   * 从 `.xzbak` 或普通 `.xlsx` 导入。
   *
   * 选中加密备份时必须给 `backupPassword`；普通表格留空即可。
   */
  importBackup: (path: string, password: string, backupPassword?: string) =>
    invoke<{ imported: number; skipped: number; errors: string[] }>("import_backup", {
      path,
      password,
      backupPassword: backupPassword && backupPassword.length > 0 ? backupPassword : null,
    }),

  touch: () => invoke<void>("touch_activity"),
  autolockCheck: () => invoke<AutolockResult>("autolock_check"),
  /** 当前自动锁定的闲置分钟数。 */
  autolockMinutes: () => invoke<number>("autolock_minutes"),
  /** 设置自动锁定的闲置分钟数，返回实际生效的值。 */
  setAutolock: (minutes: number) => invoke<number>("set_autolock", { minutes }),
};

/** 自动锁定的结果。`save_error` 有值时说明锁定前那次保存失败了。 */
export interface AutolockResult {
  locked: boolean;
  save_error: string | null;
}

/** 把后端抛出的错误转成一句人话。 */
export function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}