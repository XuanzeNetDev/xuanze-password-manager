/**
 * 璇泽密钥库 · 前端
 *
 * 布局只有一屏：左边极窄的条目列表，右边是**表格**。
 * 数据本来就是表格状的（名称 / 账号 / 密钥 / 网址 / 标签），
 * 所以直接摊开看，点一下就地编辑，不做「选中 → 再看详情」那两步。
 */

import { api as realApi, errText, kindKey, type EntryView, type ItemView } from "./api";
import { open, save } from "@tauri-apps/plugin-dialog";
import { h, icon, replaceChildren } from "./dom";
import logoUrl from "./assets/logo.png";
import { applyTheme, getTheme, watchSystemTheme, type Theme } from "./theme";
import "./style.css";

/*
 * 浏览器预览用的假后端。
 *
 * `import.meta.env.DEV` 在构建时被静态替换成 `false`，
 * 于是三元表达式里 `mockApi` 那一支会被整棵摇掉 —— `mock.ts` 连同
 * 它里面的假数据不会进入发布包 —— 安全扫描工具少一堆误报，包也小一点。
 */
const api = (
  import.meta.env.DEV
    ? (await import("./mock")).mockApi
    : realApi
) as typeof realApi;

// ─────────────────────────── 状态 ───────────────────────────

const state = {
  unlocked: false,
  /** 当前专辑：all / hot / tag:xxx / untagged */
  album: "all",
  /** 全量条目（用于算专辑计数与过滤）。 */
  allItems: [] as ItemView[],
  allCount: 0,
  hotCount: 0,
  /** 当前表格里要显示的条目。 */
  items: [] as ItemView[],
  full: new Map<string, EntryView>(),
  /** 已取出的明文。只在 shown 里有条目时才有值，锁库/隐藏时清掉。 */
  secret: new Map<string, string>(),
  selected: null as string | null,
  query: "",
  dirty: false,
  seconds: null as number | null,
  shown: new Set<string>(),
  /** 入场动画是否已经播过。true 之后的任何重建都不再播。 */
  entered: false,
};



const root = document.getElementById("app")!;
const toasts = h("div", { class: "toasts" });

// ─────────────────────────── 工具 ───────────────────────────

function toast(msg: string, sub?: string): void {
  const el = h("div", { class: "toast" }, msg, sub ? h("div", { class: "sub" }, sub) : null);
  toasts.appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    setTimeout(() => el.remove(), 180);
  }, sub ? 3000 : 1900);
}

const lastPath = () => localStorage.getItem("xz.lastVault") ?? "";

function countdown(s: number | null): string {
  if (s === null || s <= 0) return "";
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}:${String(s % 60).padStart(2, "0")}` : `${s}s`;
}

// ─────────────────────────── 锁屏 ───────────────────────────

function renderLock(msg = "", info = false): void {
  // 「库」这个概念对用户是隐藏的，界面上只分两种状态：
  //   第一次用 → 设置一个密码（注册）
  //   以后每次 → 输入这个密码（登录）
  const path = lastPath();
  if (!path) {
    renderRegister();
    return;
  }


  const pw = h("input", {
    class: "lock-input",
    type: "password",
    placeholder: "密码",
    attrs: { autocomplete: "off", spellcheck: "false" },
  });
  const msgEl = h("div", { class: `lock-msg${info ? " info" : ""}` }, msg);
  let busy = false;

  const submit = async () => {
    if (busy) return;
    if (!pw.value) {
      pw.focus();
      return;
    }
    busy = true;
    replaceChildren(msgEl, [h("span", { class: "spin" })]);
    msgEl.classList.add("info");
    try {
      await api.open(path, pw.value);
      await enter();
    } catch (e) {
      msgEl.classList.remove("info");
      // 三类错误要分开说，因为用户的下一步动作完全不同：
      //   1. 密码错 → 重输
      //   2. 这库不归本机管 → 换个文件
      //   3. 本机绑定材料丢了 → 不能再试，库救不回来了
      // 全提示成「密码不对」会让第 2、3 种情况的人一直重试一个正确密码。
      const raw = errText(e);
      if (raw.includes("绑定材料")) {
        msgEl.textContent = "本机的绑定材料丢失，这个库已无法打开";
      } else if (raw.includes("不是本机创建")) {
        msgEl.textContent = "这个库不是在本机创建的，无法打开";
      } else {
        msgEl.textContent = "密码不对";
      }
      busy = false;
      pw.select();
    }
  };

  pw.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void submit();
  });

  const go = h("button", { class: "btn primary lock-go", type: "button" }, "登录");
  go.addEventListener("click", () => void submit());

  replaceChildren(root, [
    h(
      "div",
      { class: "lock" },
      h("div", { class: "grain" }),
      h(
        "div",
        { class: "lock-inner" },
        h("img", { class: "lock-logo", src: logoUrl, alt: "" }),
        h("h1", { class: "lock-name" }, "璇泽密钥库"),
        pw,
        msgEl,
        go,
      ),
    ),
    toasts,
  ]);
}

/**
 * 首次进入：设置密码。
 *
 * 只问密码，不问路径、不问账号。文件落在应用数据目录里的一个固定位置，
 * 用户永远不需要知道它叫什么、存在哪 —— 那是实现细节，不是用户的事。
 */
function renderRegister(): void {
  const p1 = h("input", {
    class: "lock-input",
    type: "password",
    placeholder: "设置密码",
    attrs: { autocomplete: "off", spellcheck: "false" },
  });
  const p2 = h("input", {
    class: "lock-input",
    type: "password",
    placeholder: "再输一次",
    attrs: { autocomplete: "off", spellcheck: "false" },
  });
  const msgEl = h("div", { class: "lock-msg" });
  let busy = false;


  const submit = async () => {
    if (busy) return;
    if (p1.value.length < 8) {
      msgEl.textContent = "至少 8 位";
      p1.focus();
      return;
    }
    if (p1.value !== p2.value) {
      msgEl.textContent = "两次输入不一致";
      p2.select();
      return;
    }
    busy = true;

    // 建库要跑 Argon2id 1 GiB × 3 轮，约一两秒。
    // 转圈只说「在等」，说不出「在干什么」—— 改成逐条推进的文案，
    // 用户能看到进度在走，等待感会短很多。
    const steps = [
      "正在创建您的密钥库…",
      "正在生成加密密钥…",
      "正在加固您的数据…",
      "正在写入本地文件…",
      "即将完成…",
    ];
    let stepIdx = 0;
    replaceChildren(msgEl, []);
    msgEl.classList.add("info");
    msgEl.classList.add("lock-progress");
    const stepEl = h("span", { class: "progress-text" }, steps[0] ?? "");
    msgEl.appendChild(stepEl);

    // 每 900ms 推进一条，最后一条停住等结果
    const timer = window.setInterval(() => {
      stepIdx = Math.min(stepIdx + 1, steps.length - 1);
      stepEl.textContent = steps[stepIdx] ?? "";
    }, 900);

    try {
      // 用 paranoid 档（256 MiB × 4 轮），不给用户出选择题。
      //
      // 不用 maximum（1 GiB × 3 轮）：打开时瞬间占 1 GiB 内存，
      // 对日常使用没必要。256 MiB 已经让 GPU 破解很不划算，
      // 而内存峰值降到四分之一，老一点的轻薄本也能顺畅跑。
      // 强密码 + 本机绑定才是主要防线，KDF 只是最后一道。
      await api.create(p1.value, "paranoid");
      window.clearInterval(timer);
      stepEl.textContent = steps[steps.length - 1] ?? "";

      const path = await api.defaultVaultPath();
      await api.save(path);
      localStorage.setItem("xz.lastVault", path);

      await enter();
    } catch (e) {
      window.clearInterval(timer);
      msgEl.classList.remove("info");
      msgEl.classList.remove("lock-progress");
      msgEl.textContent = errText(e);
      busy = false;
    }
  };

  for (const el of [p1, p2]) {
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void submit();
    });
  }

  const go = h("button", { class: "btn primary lock-go", type: "button" }, "开始使用");
  go.addEventListener("click", () => void submit());

  replaceChildren(root, [
    h(
      "div",
      { class: "lock" },
      h("div", { class: "grain" }),
      h(
        "div",
        { class: "lock-inner" },
        h("img", { class: "lock-logo", src: logoUrl, alt: "" }),
        h("h1", { class: "lock-name" }, "璇泽密钥库"),
        h("p", { class: "lock-sub" }, "设置一个密码，以后用它进入"),
        p1,
        p2,

        msgEl,
        go,
        h("div", { class: "lock-foot" }, h("span", { class: "lock-note" }, "密码不会上传，忘了就找不回")),
      ),
    ),
    toasts,
  ]);
}

// ─────────────────────────── 主界面 ───────────────────────────

/**
 * 在两个屏幕之间做一次连贯的过渡。
 *
 * 硬切会让界面「跳」一下 —— 这是生硬感的主要来源。
 * 这里让旧界面快速淡出并轻微后退，新界面同时从略小、略模糊的状态浮上来，
 * 两者短暂交叠。读起来是「同一块空间换了内容」，而不是「换了张图」。
 *
 * 用 `element.animate()` 而不是 CSS class：过渡只发生一次，
 * 不需要在样式表里维护状态类，也不会和入场动画抢同一个属性。
 */
function swapScreen(next: () => void): void {
  const old = root.firstElementChild as HTMLElement | null;

  if (old) {
    const anim = old.animate(
      [
        { opacity: 1, transform: "scale(1)", filter: "blur(0px)" },
        { opacity: 0, transform: "scale(0.99)", filter: "blur(4px)" },
      ],
      {
        duration: 180,
        easing: "cubic-bezier(0.4, 0, 1, 1)",
        fill: "forwards",
      },
    );
    // 旧层盖在新层上面完成淡出，新层就已经在下面准备好了。
    //
    // 必须同时关掉 pointer-events：否则这 180 ms 里旧层仍在接收点击，
    // 用户快速双击会打到「已经不属于当前界面、马上就要被删掉」的节点上
    // （比如锁屏时连点两次登录，第二次落到旧闭包的 busy 标志上）。
    // 视觉上它还看得见，但已经不该再响应任何输入。
    old.style.position = "absolute";
    old.style.inset = "0";
    old.style.zIndex = "5";
    old.style.pointerEvents = "none";
    anim.finished
      .then(() => {
        old.remove();
      })
      .catch(() => {
        // 被打断就直接移除，别留残影
        old.remove();
      });
  }

  next();
}

async function enter(): Promise<void> {
  state.unlocked = true;
  state.selected = null;
  state.query = "";
  state.shown.clear();
  state.secret.clear();
  state.full.clear();
  await reload();
  swapScreen(() => renderMain());
}

async function reload(): Promise<void> {
  const st = await api.status();
  state.dirty = st.dirty;
  state.seconds = st.seconds_until_lock;
  await reloadList();
  // 表格要一次性把每条（除秘密外）的内容都摊开，所以这里必须等全部取完再渲染，
  // 否则首屏会先闪一排「…」。
  await preloadAll();
}

async function reloadList(): Promise<void> {
  const q = state.query.trim();
  // 全量先取一次：专辑计数、过滤都要用
  state.allItems = await api.all();
  state.allCount = state.allItems.length;
  const hot = await api.hot(200);
  state.hotCount = hot.length;

  if (q) {
    state.items = (await api.search(q, 200)) as ItemView[];
    return;
  }
  switch (state.album) {
    case "hot":
      state.items = hot;
      break;
    case "untagged":
      state.items = state.allItems.filter((i) => !i.tags.length);
      break;
    default: {
      const tag = state.album.startsWith("tag:") ? state.album.slice(4) : "";
      state.items = tag ? state.allItems.filter((i) => i.tags.includes(tag)) : state.allItems;
    }
  }
}

/** 取完整条目（含秘密），缓存起来供表格渲染。 */
async function fullOf(id: string): Promise<EntryView | null> {
  const hit = state.full.get(id);
  if (hit) return hit;
  try {
    const e = await api.get(id);
    state.full.set(id, e);
    return e;
  } catch {
    return null;
  }
}

async function preloadAll(): Promise<void> {
  await Promise.all(state.items.map((i) => fullOf(i.id)));
}

function renderMain(): void {
  const side = renderSide();
  const main = h("main", { class: "main" }, ...renderTable());
  // 只有第一次进入才播入场动画。之后的任何重建（切专辑、搜索、删条目、复制后刷新）
  // 都带上 entered —— 否则每点一下整个界面就重演一遍开场，廉价感就是这么来的。
  const shellClass = state.entered ? "shell entered" : "shell";
  replaceChildren(root, [h("div", { class: shellClass }, side, main), toasts]);
  state.entered = true;
}

function renderSide(): HTMLElement {
  const search = h("input", { placeholder: "搜索", value: state.query, attrs: { spellcheck: "false" } });
  search.addEventListener("input", () => {
    state.query = search.value;
    scheduleSearch(search);
  });

  // 左栏是「专辑」目录：按标签聚合。搜索时临时切到搜索结果视图。
  const albums = buildAlbums();
  const searching = state.query.trim().length > 0;

  const albumRows: HTMLElement[] = [];
  const mkAlbum = (key: string, label: string, count: number, glyphCh: string) => {
    const on = !searching && state.album === key;
    const r = h(
      "div",
      { class: `arow${on ? " on" : ""}` },
      h("span", { class: "aglyph" }, glyphCh),
      h("span", { class: "aname" }, label),
      h("span", { class: "acount" }, String(count)),
    );
    r.addEventListener("click", () => {
      state.album = key;
      state.query = "";
      state.selected = null;
      void (async () => {
        await reloadList();
        renderMain();
      })();
    });
    return r;
  };

  if (searching) {
    albumRows.push(h("div", { class: "ahr" }, "搜索结果"));
    albumRows.push(
      h("div", { class: "aresult" }, `${state.items.length} 条`),
    );
  } else {
    albumRows.push(mkAlbum("all", "全部", state.allCount, "▤"));
    albumRows.push(mkAlbum("hot", "常用", state.hotCount, "★"));
    const tagged = albums.filter((a) => a.key !== "untagged");
    if (tagged.length) {
      albumRows.push(h("div", { class: "ahr" }, "专辑"));
      for (const a of tagged) albumRows.push(mkAlbum(a.key, a.label, a.count, "#"));
    }
    const untagged = albums.find((a) => a.key === "untagged");
    if (untagged && untagged.count > 0) {
      albumRows.push(h("div", { class: "ahr" }, "其他"));
      albumRows.push(mkAlbum("untagged", "未分类", untagged.count, "·"));
    }
  }

  const mk = (name: string, title: string, fn: () => void) => {
    const b = h("button", { class: "ib", type: "button", title }, icon(name));
    b.addEventListener("click", fn);
    return b;
  };

  return h(
    "aside",
    { class: "side" },
    h("div", { class: "side-top" }, h("div", { class: "search" }, icon("search"), search)),
    h("div", { class: "side-list" }, ...albumRows),
    h(
      "div",
      { class: "side-foot" },
      // 不提供导入/导出：
      //   导入 —— 新版浏览器的密码库（v20）拿不到；
      //   导出 —— 明文落盘等于把加密白做了，数据只能留在软件里。
      mk("gear", "设置", () => openSettings()),
      h("div", { class: "grow" }),
      h("span", { class: "cd" }, countdown(state.seconds)),
    ),
  );
}

/** 按标签聚合出专辑列表。 */
function buildAlbums(): { key: string; label: string; count: number }[] {
  const m = new Map<string, number>();
  let untagged = 0;
  for (const it of state.allItems) {
    if (!it.tags.length) untagged++;
    for (const tg of it.tags) m.set(tg, (m.get(tg) ?? 0) + 1);
  }
  const list = [...m.entries()]
    .map(([label, count]) => ({ key: `tag:${label}`, label, count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  list.push({ key: "untagged", label: "未分类", count: untagged });
  return list;
}

function mkNewFirst(): HTMLElement {
  const b = h("button", { class: "btn primary", type: "button" }, "新建第一条");
  b.addEventListener("click", () => openEditor(null));
  return b;
}

function albumTitle(): string {
  if (state.query.trim()) return "搜索结果";
  if (state.album === "hot") return "常用";
  if (state.album === "untagged") return "未分类";
  if (state.album.startsWith("tag:")) return state.album.slice(4);
  return "全部";
}

function t_kind(k: number): string {
  const m: Record<string, string> = {
    login: "登录",
    api_key: "密钥",
    note: "笔记",
    card: "卡片",
    credential: "凭据",
  };
  return m[kindKey(k)] ?? "密钥";
}

// ─────────────────────────── 表格 ───────────────────────────

/** 表格列定义：字段名 + 是否敏感 + 宽度。 */
interface Col {
  key: string;
  label: string;
  secret?: boolean;
  width: string;
}

function columnsOf(): Col[] {
  // 基础列固定，自定义字段动态补在后面（按出现次数排序，别让表格横着长成蜈蚣）
  const cols: Col[] = [
    { key: "name", label: "名称", width: "minmax(150px,1.4fr)" },
    { key: "kind", label: "类型", width: "82px" },
    { key: "username", label: "账号", width: "minmax(110px,1fr)" },
    { key: "secret", label: "密码 / 密钥", secret: true, width: "minmax(170px,1.6fr)" },
    { key: "url", label: "网址", width: "minmax(140px,1.4fr)" },
  ];
  // 表格只留核心信息：名称 / 类型 / 账号 / 密钥 / 网址 / 专辑。
  // 自定义字段（org、region 这类）只在编辑里看，摊进表格纯属噪音。
  cols.push({ key: "tags", label: "专辑", width: "minmax(80px,0.7fr)" });
  return cols;
}

/**
 * 造一个表格行。
 *
 * 列定义走 `style.setProperty("--cols", ...)` 而不是 `style` 属性字符串 ——
 * 这样不需要 CSP 的 `unsafe-inline`，而 `unsafe-inline` 一旦开着，
 * 任何被注入的内联 `<style>` 都会生效（CSS 密室、@import 外带）。
 * 值本身来自常量表 `columnsOf()`，不接受任何用户数据。
 */
function makeRow(cls: string, ...cells: HTMLElement[]): HTMLElement {
  const row = h("div", { class: cls }, ...cells);
  row.style.setProperty(
    "--cols",
    `${columnsOf().map((c) => c.width).join(" ")} 40px`,
  );
  return row;
}

/**
 * 只更新行的选中态，不重建 DOM。
 *
 * 选中是纯视觉状态：换掉 `.sel` 这个 class 就够了。
 * 走整页重渲染会把入场动画全部重放一遍，看起来很廉价。
 */
function updateSelection(): void {
  const rows = root.querySelectorAll<HTMLElement>(".table .tr:not(.th)");
  let i = 0;
  for (const row of rows) {
    // 行与 items 一一对应（表头是 .th，已被排除）
    const item = state.items[i];
    if (item) {
      const on = item.id === state.selected;
      row.classList.toggle("sel", on);
      // 键盘上下移动时把选中行带进视野，否则移出屏幕就看不见了
      if (on) row.scrollIntoView({ block: "nearest" });
    }
    i++;
  }
}

/**
 * 方向键移动选中项。
 *
 * `delta` 为 +1 往下、-1 往上。没有选中时，↓ 选第一条、↑ 选最后一条 ——
 * 这样按第一下就有反馈，不用先点一下再用键盘。
 */
function moveSelection(delta: number): void {
  const list = state.items;
  if (!list.length) return;
  const cur = list.findIndex((i) => i.id === state.selected);
  let next: number;
  if (cur < 0) {
    next = delta > 0 ? 0 : list.length - 1;
  } else {
    next = Math.min(Math.max(cur + delta, 0), list.length - 1);
  }
  const target = list[next];
  if (!target || target.id === state.selected) return;
  state.selected = target.id;
  updateSelection();
}

function renderTable(): HTMLElement[] {
  if (!state.unlocked) return [];
  const list = state.items;
  if (!list.length) {
    return [
      h("div", { class: "tbar" }, h("div", { class: "tbar-t" }, albumTitle())),
      h("div", { class: "tempty" }, h("div", {}, state.query.trim() ? "没有匹配" : "还没有条目"),
        mkNewFirst()),
    ];
  }

  const cols = columnsOf();

  const head = makeRow(
    "tr th",
    ...cols.map((c) => h("div", { class: "td" }, c.label)),
    h("div", { class: "td" }),
  );

  const body = list.map((item) => {
    const e = state.full.get(item.id);
    const cells: HTMLElement[] = cols.map((c) => {
      if (!e) return h("div", { class: "td dim" }, "…");
      return renderCell(e, c);
    });
    const acts = h("div", { class: "td tacts" });
    const edit = h("button", { class: "ib sm", type: "button", title: "编辑" }, icon("pencil"));
    edit.addEventListener("click", () => openEditor(e ?? null, item.id));
    const del = h("button", { class: "ib sm", type: "button", title: "删除" }, "×");
    del.addEventListener("click", () => void doDelete(item.id, item.name));
    acts.append(edit, del);
    cells.push(acts);

    const tr = makeRow(`tr${state.selected === item.id ? " sel" : ""}`, ...cells);
    tr.addEventListener("click", (ev) => {
      if ((ev.target as HTMLElement).closest("button")) return;
      // 只切换选中态，**不重建页面**。
      //
      // 之前这里调 renderMain()，等于点一下就把整个界面推倒重来：
      // 所有行的入场动画重播一遍，用户看到的是「整页闪一下」。
      // 选中只是改一个 class，没必要付出这个代价。
      if (state.selected === item.id) return;
      state.selected = item.id;
      updateSelection();
    });
    return tr;
  });

  const newBtn = h("button", { class: "btn", type: "button" }, "＋ 新建");
  newBtn.addEventListener("click", () => openEditor(null));

  return [
    h(
      "div",
      { class: "tbar" },
      h("div", { class: "tbar-t" }, albumTitle()),
      h("div", { class: "tbar-n" }, `${list.length} 条`),
      h("div", { class: "grow" }),
      newBtn,
    ),
    h("div", { class: "table" }, head, ...body),
  ];
}

function renderCell(e: EntryView, c: Col): HTMLElement {
  if (c.key === "name") {
    return h("div", { class: "td strong", title: e.name }, e.name);
  }
  if (c.key === "kind") {
    // e.kind 已经是字符串（login / api_key / note / card / credential）
    const map: Record<string, string> = {
      login: "登录",
      api_key: "密钥",
      note: "笔记",
      card: "卡片",
      credential: "凭据",
    };
    return h("div", { class: "td dim" }, map[e.kind] ?? "密钥");
  }
  if (c.key === "username") {
    return h("div", { class: "td mono", title: e.username }, e.username || "—");
  }
  if (c.key === "secret") {
    const shown = state.shown.has(e.id);
    // 已取过的明文走缓存，不重复发 IPC。
    //
    // 原先这里每次渲染都无条件调 `api.reveal()`，而 `state.full` 存的是
    // EntryView —— 后端刻意不在里面放 secret，所以那行 `const text = ...`
    // 从头到尾都是死代码。现在明文单独放 state.secret，锁库和隐藏时能精确清掉。
    const cached = state.secret.get(e.id);
    const cell = h(
      "div",
      { class: `td mono secret-cell${shown ? " on" : ""}` },
      shown ? (cached ?? "加载中…") : "•••••••",
    );
    if (shown && cached === undefined) {
      void api.reveal(e.id).then((v) => {
        state.secret.set(e.id, v);
        cell.textContent = v;
      }).catch(() => {
        cell.textContent = "—";
      });
    }
    const eye = h("button", { class: "ib sm", type: "button", title: shown ? "隐藏" : "显示" }, icon(shown ? "eyeOff" : "eye"));
    eye.addEventListener("click", () => {
      // 只换这一个单元格的内容和图标，不重建整页。
      // 之前走 renderMain()，点一次「显示」整张表的入场动画就重播一遍。
      const willShow = !state.shown.has(e.id);
      if (willShow) state.shown.add(e.id);
      else state.shown.delete(e.id);

      cell.classList.toggle("on", willShow);
      if (!willShow) {
        cell.textContent = "•••••••";
        // 隐藏就把明文从内存里拿掉，不留到下次。
        state.secret.delete(e.id);
      } else {
        const cached = state.secret.get(e.id);
        if (cached !== undefined) {
          cell.textContent = cached;
        } else {
          cell.textContent = "加载中…";
          void api
            .reveal(e.id)
            .then((v) => {
              state.secret.set(e.id, v);
              cell.textContent = v;
            })
            .catch(() => {
              cell.textContent = "—";
            });
        }
      }
      replaceChildren(eye, [icon(willShow ? "eyeOff" : "eye")]);
      eye.title = willShow ? "隐藏" : "显示";
    });
    const cp = h("button", { class: "ib sm", type: "button", title: "复制" }, icon("copy"));
    cp.addEventListener("click", () => void copySecret(e.id, e.name));
    return h("div", { class: "td secret-wrap" }, cell, h("span", { class: "cellacts" }, eye, cp));
  }
  if (c.key === "url") {
    return h("div", { class: "td mono dim", title: e.url }, e.url || "—");
  }
  if (c.key === "tags") {
    return h(
      "div",
      { class: "td" },
      e.tags.length
        ? h("div", { class: "tags" }, ...e.tags.slice(0, 3).map((t) => h("span", { class: "tag" }, t)))
        : h("span", { class: "dim" }, "—"),
    );
  }
  if (c.key.startsWith("f:")) {
    const name = c.key.slice(2);
    const f = e.fields.find((x) => x.name === name);
    if (!f) return h("div", { class: "td dim" }, "—");
    if (f.secret) return h("div", { class: "td mono dim" }, "••••••");
    return h("div", { class: "td mono", title: f.value }, f.value);
  }
  return h("div", { class: "td dim" }, "—");
}

// ─────────────────────────── 动作 ───────────────────────────

async function autosave(): Promise<void> {
  const p = lastPath();
  if (!p) return;
  try {
    await api.save(p);
    const st = await api.status();
    state.dirty = st.dirty;
  } catch (e) {
    toast(`保存失败：${errText(e)}`);
  }
}

async function copySecret(id: string, name: string): Promise<void> {
  try {
    await api.copy(await api.reveal(id), true);
    void api.recordUse(id);
    toast(`已复制：${name}`, "15 秒后清除剪贴板");
  } catch (e) {
    toast(errText(e));
  }
}

let searchTimer = 0;
function scheduleSearch(input: HTMLInputElement): void {
  clearTimeout(searchTimer);
  searchTimer = window.setTimeout(async () => {
    await reloadList();
    await preloadAll();
    renderMain();
    const el = document.querySelector<HTMLInputElement>(".search input");
    if (el) {
      el.focus();
      el.setSelectionRange(input.value.length, input.value.length);
    }
  }, 50);
}

async function doDelete(id: string, name: string): Promise<void> {
  if (!confirm(`删除「${name}」？无法撤销。`)) return;
  try {
    await api.deleteEntry(id);
    state.full.delete(id);
    await autosave();
    await reload();
    await preloadAll();
    renderMain();
    toast("已删除");
  } catch (e) {
    toast(errText(e));
  }
}

async function doLock(): Promise<void> {
  try {
    await api.lock();
    state.unlocked = false;
    state.items = [];
    state.full.clear();
    state.shown.clear();
    state.secret.clear();
    state.entered = false;
    swapScreen(() => renderLock("已锁定", true));
  } catch (e) {
    toast(errText(e));
  }
}

// ─────────────────────────── 浮层 ───────────────────────────

function closeModal(): void {
  // 弹窗里可能有密码 / 密钥明文，移除节点前先清空，
  // 别让它们以「不可见的 input.value」形式留在内存里等 GC。
  for (const el of document.querySelectorAll<HTMLInputElement>(
    ".panel input, .panel textarea",
  )) {
    el.value = "";
  }
  document.querySelector(".scrim")?.remove();
}

function openModal(title: string, body: HTMLElement[], foot: HTMLElement[]): void {
  closeModal();
  const scrim = h(
    "div",
    { class: "scrim" },
    h(
      "div",
      { class: "panel" },
      h("div", { class: "phead" }, title),
      h("div", { class: "pbody" }, ...body),
      h("div", { class: "pfoot" }, ...foot),
    ),
  );
  scrim.addEventListener("click", (e) => {
    if (e.target === scrim) closeModal();
  });
  document.body.appendChild(scrim);
}

function row(label: string, el: HTMLElement): HTMLElement {
  return h("div", { class: "fld" }, h("label", { class: "flbl" }, label), el);
}

async function openEditor(existing: EntryView | null, id?: string): Promise<void> {
  const e = existing ?? (id ? await fullOf(id) : null);

  const name = h("input", { class: "in", value: e?.name ?? "" });
  const user = h("input", { class: "in", value: e?.username ?? "" });
  const url = h("input", { class: "in", value: e?.url ?? "" });
  const secret = h("input", { class: "in mono", type: "password", placeholder: e ? "留空不改" : "" });
  const notes = h("textarea", { class: "in" }) as HTMLTextAreaElement;
  if (e?.notes) notes.value = e.notes;

  const kind = h("select", { class: "in" }) as HTMLSelectElement;
  for (const k of ["login", "api_key", "note", "card", "credential"]) {
    const o = document.createElement("option");
    o.value = k;
    o.textContent = t_kind(["login", "api_key", "note", "card", "credential"].indexOf(k));
    if ((e?.kind ?? "api_key") === k) o.selected = true;
    kind.appendChild(o);
  }

  // ── 专辑（内部仍存成 tags，但界面上叫「专辑」，因为它就是分类）
  //
  //   - 一个条目可以属于多个专辑；
  //   - 已经有专辑时，下面直接列出来点选，不用记拼写；
  //   - 全不选就是「未分类」——留空是合法状态，不强制归类。
  const tags = [...(e?.tags ?? [])];
  const tagBox = h("div", { class: "tag-edit" });
  const tagIn = h("input", { placeholder: "新建专辑，回车即可" });

  const draw = () => {
    replaceChildren(tagBox, []);
    for (const tg of tags) {
      const c = h("span", { class: "tag tagx" }, `${tg} ×`);
      c.addEventListener("click", () => {
        tags.splice(tags.indexOf(tg), 1);
        draw();
        drawSuggest();
      });
      tagBox.appendChild(c);
    }
    tagBox.appendChild(tagIn);
  };

  // 已有专辑的候选：点一下就选中；已选中的从候选里消失（在上面的框里显示）
  // 已有专辑：整行列表，点一行就选中/取消。
  // 之前是小圆角标签，视觉上像装饰、也点不准 —— 换成整行按钮。
  const known = buildAlbums()
    .filter((a) => a.key !== "untagged")
    .map((a) => ({ label: a.label, count: a.count }));
  const suggest = h("div", { class: "album-list" });

  const drawSuggest = () => {
    replaceChildren(suggest, []);
    if (!known.length) {
      suggest.appendChild(
        h("div", { class: "album-empty" }, "还没有专辑，在上面输入一个就会创建"),
      );
      return;
    }
    for (const { label, count } of known) {
      const on = tags.includes(label);
      const row = h(
        "button",
        { class: `album-row${on ? " on" : ""}`, type: "button", title: on ? "取消这个专辑" : "加入这个专辑" },
        h("span", { class: `album-check${on ? " on" : ""}` }, on ? "✓" : ""),
        h("span", { class: "album-name" }, label),
        h("span", { class: "album-n" }, String(count)),
      );
      row.addEventListener("click", () => {
        if (on) tags.splice(tags.indexOf(label), 1);
        else tags.push(label);
        draw();
        drawSuggest();
      });
      suggest.appendChild(row);
    }
    if (!tags.length) {
      suggest.appendChild(h("div", { class: "album-tip" }, "都不选 → 归入「未分类」"));
    }
  };

  tagIn.addEventListener("keydown", (ev) => {
    const k = ev as KeyboardEvent;
    if (k.key === "Enter" && tagIn.value.trim()) {
      k.preventDefault();
      const v = tagIn.value.trim();
      if (!tags.includes(v)) tags.push(v);
      tagIn.value = "";
      draw();
      drawSuggest();
      tagIn.focus();
    }
  });
  draw();
  drawSuggest();

  const fields = (e?.fields ?? []).map((f) => ({ ...f }));
  const fBox = h("div", {});
  const drawF = () => {
    replaceChildren(fBox, []);
    fields.forEach((f, i) => {
      const a = h("input", { type: "text", placeholder: "字段名", value: f.name });
      a.addEventListener("input", () => { const c = fields[i]; if (c) c.name = a.value; });
      const b = h("input", { type: "text", placeholder: "值", value: f.value });
      b.addEventListener("input", () => { const c = fields[i]; if (c) c.value = b.value; });
      const cb = h("input", { type: "checkbox" }) as HTMLInputElement;
      cb.checked = f.secret;
      cb.addEventListener("change", () => { const c = fields[i]; if (c) c.secret = cb.checked; });
      const x = h("button", { class: "ib sm", type: "button" }, "×");
      x.addEventListener("click", () => { fields.splice(i, 1); drawF(); });
      fBox.appendChild(h("div", { class: "field-edit" }, a, b, h("label", { class: "chk" }, cb, "敏感"), x));
    });
  };
  drawF();

  const addF = h("button", { class: "btn sm", type: "button" }, "＋ 字段");
  addF.addEventListener("click", () => {
    fields.push({ name: "", value: "", secret: false });
    drawF();
  });

  const err = h("div", { class: "err" });
  const cancel = h("button", { class: "btn", type: "button" }, "取消");
  cancel.addEventListener("click", () => closeModal());
  const ok = h("button", { class: "btn primary", type: "button" }, "保存");
  ok.addEventListener("click", async () => {
    if (!name.value.trim()) return void (err.textContent = "名称不能为空");
    try {
      const savedId = await api.saveEntry({
        id: e?.id ?? "",
        kind: kind.value,
        name: name.value,
        username: user.value,
        secret: secret.value,
        url: url.value,
        notes: notes.value,
        tags,
        fields: fields.map((f) => ({ name: f.name, value: f.value, secret: f.secret })),
        expires_at: e?.expires_at ?? 0,
      });
      state.full.delete(savedId);
      await autosave();
      closeModal();
      await reload();
      await preloadAll();
      renderMain();
      toast("已保存");
    } catch (ex) {
      err.textContent = errText(ex);
    }
  });

  openModal(
    e ? "编辑" : "新建条目",
    [
      row("名称", name),
      h("div", { class: "two" }, row("类型", kind), row("账号", user)),
      row("密码 / 密钥", secret),
      row("网址", url),
      h("div", { class: "fld" }, h("label", { class: "flbl" }, "专辑"), tagBox, suggest),
      h("div", { class: "fld" }, h("label", { class: "flbl" }, "自定义字段"), fBox, addF),
      row("备注", notes),
      err,
    ],
    [cancel, ok],
  );
  setTimeout(() => name.focus(), 40);
}

/**
 * 修改主密码。
 *
 * 三个输入：原密码、新密码、再输一次。原密码交给后端校验 ——
 * 光靠「会话已解锁」不够，那样有人趁你离开座位就能把密码换掉。
 */
function openRekey(): void {
  const oldPw = h("input", {
    class: "in",
    type: "password",
    attrs: { placeholder: "原密码", autocomplete: "off" },
  }) as HTMLInputElement;
  const newPw = h("input", {
    class: "in",
    type: "password",
    attrs: { placeholder: "新密码（至少 8 位）", autocomplete: "off" },
  }) as HTMLInputElement;
  const again = h("input", {
    class: "in",
    type: "password",
    attrs: { placeholder: "再输一次新密码", autocomplete: "off" },
  }) as HTMLInputElement;
  const msg = h("div", { class: "err" });

  let busy = false;
  const cancel = h("button", { class: "btn", type: "button" }, "取消");
  cancel.addEventListener("click", () => closeModal());
  const go = h("button", { class: "btn primary", type: "button" }, "确认修改");

  go.addEventListener("click", async () => {
    if (busy) return;
    msg.textContent = "";
    if (!oldPw.value) {
      msg.textContent = "请输入原密码";
      oldPw.focus();
      return;
    }
    if (newPw.value.length < 8) {
      msg.textContent = "新密码至少 8 位";
      newPw.focus();
      return;
    }
    if (newPw.value !== again.value) {
      msg.textContent = "两次输入不一致";
      again.select();
      return;
    }
    const p = lastPath();
    if (!p) {
      msg.textContent = "找不到库文件";
      return;
    }
    busy = true;
    go.disabled = true;
    go.textContent = "处理中…";
    try {
      await api.rekey(oldPw.value, newPw.value, p);
      closeModal();
      toast("密码已修改", "下次请用新密码登录");
    } catch (e) {
      // 换密码要走两轮 Argon2（最高档），失败时别把按钮一直卡住
      msg.textContent = errText(e);
      busy = false;
      go.disabled = false;
      go.textContent = "确认修改";
    }
  });

  openModal(
    "修改密码",
    [
      oldPw,
      newPw,
      again,
      msg,
      h("div", { class: "shint" }, "密码不会上传；忘记密码数据无法恢复。"),
    ],
    [cancel, go],
  );
}

function openSettings(): void {
  const seg = (opts: [string, string][], cur: string, on: (v: string) => void) => {
    const box = h("div", { class: "seg" });
    for (const [v, label] of opts) {
      const b = h("button", { class: v === cur ? "on" : "", type: "button" }, label);
      b.addEventListener("click", () => {
        for (const c of box.children) c.classList.remove("on");
        b.classList.add("on");
        on(v);
      });
      box.appendChild(b);
    }
    return box;
  };

  const ok = h("button", { class: "btn primary", type: "button" }, "完成");
  ok.addEventListener("click", () => closeModal());

  // 改密码：必须验证原密码。
  //
  // 这里以前是「不设密码」开关 —— 勾一下就调 rekey("") 把库改成空密码，
  // 等于把加密库变成谁都能开的文件，而且没有二次确认。已删除。
  const rekeyBtn = h("button", { class: "btn", type: "button" }, "修改密码");
  rekeyBtn.addEventListener("click", () => {
    closeModal();
    openRekey();
  });

  openModal(
    "设置",
    [
      setRow("主题", null, seg([["dark", "暗"], ["light", "亮"], ["auto", "跟随系统"]], getTheme(), (v) => {
        applyTheme(v as Theme);
      })),
      setRow(
        "主密码",
        "修改后旧密码立即失效，数据用新密码重新封装。",
        rekeyBtn,
      ),
      setRow(
        "导入 / 导出",
        "Excel 表格，按专辑分表。导出的是明文，两边都需要再输一次主密码。",
        h("div", { class: "row2" },
          (() => {
            const b = h("button", { class: "btn", type: "button" }, "导入");
            b.addEventListener("click", () => {
              closeModal();
              openImport();
            });
            return b;
          })(),
          (() => {
            const b = h("button", { class: "btn", type: "button" }, "导出");
            b.addEventListener("click", () => {
              closeModal();
              openExport();
            });
            return b;
          })(),
        ),
      ),
      setRow(
        "退出登录",
        "回到密码界面。数据不会丢，下次输入密码即可继续。",
        (() => {
          const b = h("button", { class: "btn danger", type: "button" }, "退出登录");
          b.addEventListener("click", () => {
            closeModal();
            void doLock();
          });
          return b;
        })(),
      ),
      setRow(
        "关于",
        "璇泽密钥库 1.0.0 · 璇泽网络科技出品",
        (() => {
          const b = h("button", { class: "btn", type: "button" }, "关于我们");
          b.addEventListener("click", () => {
            closeModal();
            openAbout();
          });
          return b;
        })(),
      ),
    ],
    [ok],
  );
}

/**
 * 从 Excel 导入。格式与导出严格对称。
 *
 * 表头必须是导出的那一套（名称/类型/账号/密码/网址/专辑/备注/更新时间/自定义字段），
 * 每张工作表对应一个专辑。表头对不上就跳过整张表 —— 不去猜列序，
 * 猜错会把密码塞进用户名。
 *
 * 同样要求再输一次主密码：导入会改动库内容。
 */
function openImport(): void {
  const pw = h("input", {
    class: "in",
    type: "password",
    attrs: { placeholder: "主密码", autocomplete: "off" },
  }) as HTMLInputElement;
  const msg = h("div", { class: "err" });

  let busy = false;
  const cancel = h("button", { class: "btn", type: "button" }, "取消");
  cancel.addEventListener("click", () => closeModal());
  const go = h("button", { class: "btn primary", type: "button" }, "选择文件并导入");

  go.addEventListener("click", async () => {
    if (busy) return;
    msg.textContent = "";
    if (!pw.value) {
      msg.textContent = "请输入主密码";
      pw.focus();
      return;
    }

    busy = true;
    go.disabled = true;
    go.textContent = "处理中…";
    try {
      const picked = await open({
        title: "选择要导入的 Excel",
        multiple: false,
        directory: false,
        filters: [{ name: "Excel 表格", extensions: ["xlsx"] }],
      });
      const path = typeof picked === "string" ? picked : null;
      if (!path) {
        busy = false;
        go.disabled = false;
        go.textContent = "选择文件并导入";
        return;
      }

      const r = await api.importXlsx(path, pw.value);
      closeModal();
      await reloadList();
      await preloadAll();
      renderMain();
      if (r.imported === 0) {
        toast("没有导入任何条目", `跳过 ${r.skipped} 条（重复或格式不符）`);
      } else {
        toast(`已导入 ${r.imported} 条`, r.skipped > 0 ? `跳过 ${r.skipped} 条` : "");
      }
    } catch (e) {
      msg.textContent = errText(e);
      busy = false;
      go.disabled = false;
      go.textContent = "选择文件并导入";
    }
  });

  pw.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void go.click();
  });

  openModal(
    "导入 Excel",
    [
      h(
        "div",
        { class: "shint" },
        "文件格式必须与本软件导出的表格一致：表头固定，每张工作表对应一个专辑。",
      ),
      pw,
      msg,
      h(
        "div",
        { class: "shint" },
        "名称和账号都相同的条目会被跳过，同一个文件可以重复导入。",
      ),
    ],
    [cancel, go],
  );
  pw.focus();
}


/**
 * 导出为 Excel。**必须再输一次主密码**。
 *
 * 这是唯一一个能把全部密钥一次性倒出来的入口，导出的是明文。
 * 只判断「已解锁」就放行，等于给同机任何进程开一扇门 ——
 * 重输密码把这一步拉回「只有知道主密码的人能做」。
 *
 * 流程：输密码 → 选位置（系统另存为）→ 写盘。
 * 三张表起步：「全部」+ 每个专辑一张。
 */
function openExport(): void {
  const pw = h("input", {
    class: "in",
    type: "password",
    attrs: { placeholder: "主密码", autocomplete: "off" },
  }) as HTMLInputElement;
  const msg = h("div", { class: "err" });

  let busy = false;
  const cancel = h("button", { class: "btn", type: "button" }, "取消");
  cancel.addEventListener("click", () => closeModal());
  const go = h("button", { class: "btn primary", type: "button" }, "选择位置并导出");

  go.addEventListener("click", async () => {
    if (busy) return;
    msg.textContent = "";
    if (!pw.value) {
      msg.textContent = "请输入主密码";
      pw.focus();
      return;
    }

    busy = true;
    go.disabled = true;
    go.textContent = "处理中…";
    try {
      // 先让用户选位置。取消就什么都不做 —— 不要先输密码再告诉人家取消了。
      const path = await save({
        title: "导出为 Excel",
        defaultPath: `璇泽密钥库-${new Date().toISOString().slice(0, 10)}.xlsx`,
        filters: [{ name: "Excel 表格", extensions: ["xlsx"] }],
      });
      if (!path) {
        busy = false;
        go.disabled = false;
        go.textContent = "选择位置并导出";
        return;
      }

      const n = await api.exportXlsx(path, pw.value);
      closeModal();
      toast(`已导出 ${n} 条`, "文件是明文，用完请及时删除");
    } catch (e) {
      msg.textContent = errText(e);
      busy = false;
      go.disabled = false;
      go.textContent = "选择位置并导出";
    }
  });

  for (const el of [pw]) {
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void go.click();
    });
  }

  openModal(
    "导出 Excel",
    [
      h(
        "div",
        { class: "shint" },
        "导出的文件是明文，任何拿到它的人都能看到全部账号密码。",
      ),
      pw,
      msg,
      h(
        "div",
        { class: "shint" },
        "按专辑分表：每个专辑一张工作表，另有一张包含全部条目。",
      ),
    ],
    [cancel, go],
  );
  pw.focus();
}

/** 关于我们：产品信息 + 开源声明。 */

function openAbout(): void {
  const ok = h("button", { class: "btn primary", type: "button" }, "知道了");
  ok.addEventListener("click", () => closeModal());

  const kv = (k: string, v: string): HTMLElement =>
    h(
      "div",
      { class: "about-kv" },
      h("span", { class: "about-k" }, k),
      h("span", { class: "about-v" }, v),
    );

  openModal(
    "关于我们",
    [
      h(
        "div",
        { class: "about-head" },
        h("div", { class: "about-name" }, "璇泽密钥库"),
        h("div", { class: "about-sub" }, "璇泽网络科技"),
      ),

      h(
        "div",
        { class: "about-rows" },
        kv("版本", "1.0.0"),
        kv("许可证", "PolyForm Noncommercial 1.0.0"),
        kv("数据位置", "仅本机，不上传任何服务器"),
      ),

      h("h4", { class: "about-h" }, "开源声明"),
      h(
        "p",
        { class: "about-p" },
        "本项目开放源代码，目的是让任何人都能审查这套加密实现——" +
          "密码管理器的安全性不该建立在「相信我们」之上，而应该能被验证。",
      ),
      h(
        "p",
        { class: "about-p" },
        "如果你对产品有不满，可以自行下载源代码修改，做成符合自己需要的版本。",
      ),
      h(
        "p",
        { class: "about-p strong" },
        "但请遵守许可证：可用于个人使用、学习研究、非营利组织，不得用于商业用途，",
        "也不得将修改后的版本作为商业产品分发或销售。",
      ),

      h("h4", { class: "about-h" }, "关于更新"),
      h(
        "p",
        { class: "about-p" },
        "我们会持续维护这个项目，定期发布更新。使用中遇到问题或有建议，" +
          "欢迎反馈——每一条都会被认真看。感谢支持。",
      ),

      h(
        "div",
        { class: "about-foot" },
        h("span", {}, "璇泽网络科技"),
        h("span", { class: "about-dot" }, "·"),
        h("span", {}, "璇泽系列产品"),
      ),
    ],
    [ok],
  );
}

function setRow(label: string, hint: string | null, right: HTMLElement): HTMLElement {
  return h(
    "div",
    { class: "srow-set" },
    h("div", {}, h("div", { class: "slabel" }, label), hint ? h("div", { class: "shint" }, hint) : null),
    right,
  );
}

// ─────────────────────────── 快捷键 ───────────────────────────

function onKey(e: KeyboardEvent): void {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target as HTMLElement).tagName);

  // 先拦开发工具快捷键，再走业务快捷键。
  //
  // Rust 侧也注入了一份同样的拦截（lib.rs），这里是第二道。
  // 为什么值得做两遍：这软件界面上最敏感的东西就是解密后的明文，
  // 控制台一开，`await invoke('list_all')` 就把整个库打出来了。
  // 多一层成本几乎为零，漏一层的代价是全部加密工作白做。
  //
  // 这段在开发版也会生效 —— 调试时用 Rust 侧自动打开的 devtools
  // 就行，不靠快捷键。
  const k = e.key.toLowerCase();
  if (e.key === "F12" || (e.ctrlKey && e.shiftKey && /^[ijc]$/.test(k)) || (e.ctrlKey && k === "u")) {
    e.preventDefault();
    e.stopPropagation();
    return;
  }

  if (e.ctrlKey && !e.shiftKey && e.key.toLowerCase() === "k" && state.unlocked) {
    e.preventDefault();
    document.querySelector<HTMLInputElement>(".search input")?.focus();
    return;
  }
  if (e.ctrlKey && !e.shiftKey && e.key.toLowerCase() === "n" && state.unlocked) {
    e.preventDefault();
    void openEditor(null);
    return;
  }
  if (e.ctrlKey && !e.shiftKey && e.key.toLowerCase() === "l" && state.unlocked) {
    e.preventDefault();
    void doLock();
    return;
  }
  if (e.ctrlKey && e.shiftKey && /^[1-9]$/.test(e.key) && state.unlocked) {
    e.preventDefault();
    const idx = Number.parseInt(e.key, 10) - 1;
    void (async () => {
      try {
        toast(`已复制：${await api.copyByHeat(idx)}`, "15 秒后清除剪贴板");
        await reloadList();
        await preloadAll();
        renderMain();
      } catch (err) {
        toast(errText(err));
      }
    })();
    return;
  }
  if (e.key === "Escape") {
    closeModal();
    return;
  }
  if (typing) return;
  // 方向键在列表里移动选中。放在 typing 判断之后 ——
  // 正在输入框里打字时，↑↓ 应该留给光标/自动补全。
  if (state.unlocked && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
    e.preventDefault();
    moveSelection(e.key === "ArrowDown" ? 1 : -1);
    return;
  }
  if (state.selected && e.key === "Enter") {
    e.preventDefault();
    const it = state.items.find((i) => i.id === state.selected);
    if (it) void copySecret(it.id, it.name);
  }
}

// ─────────────────────────── 启动 ───────────────────────────

async function boot(): Promise<void> {
  // 预览用：?theme=light / ?theme=dark 直接指定主题，方便对照两套配色。
  // 只在开发构建里生效 —— 发布版不该有能改变行为的 URL 参数入口。
  const forcedTheme = import.meta.env.DEV
    ? new URLSearchParams(location.search).get("theme")
    : null;
  if (forcedTheme === "light" || forcedTheme === "dark") {
    applyTheme(forcedTheme);
  } else {
    applyTheme();
  }
  watchSystemTheme();

  // 流线型背景：单独一层，固定在 body 最前，不参与任何重渲染。
  // 三层各自平移 —— 只走 transform，不触发 layout。
  document.body.prepend(h("div", { class: "flow" }, h("i"), h("i"), h("i")));

  document.addEventListener("keydown", onKey);

  // 右键菜单里有个「检查」，是打开控制台的另一条路。直接禁掉。
  // Rust 侧也拦了一份，同样是双保险。
  document.addEventListener("contextmenu", (e) => e.preventDefault());
  let lastTouch = 0;
  const touch = () => {
    const now = Date.now();
    if (now - lastTouch < 6000) return;
    lastTouch = now;
    if (state.unlocked) void api.touch();
  };
  document.addEventListener("mousemove", touch, { passive: true });
  document.addEventListener("click", touch);
  document.addEventListener("keydown", touch);

  setInterval(async () => {
    if (!state.unlocked) return;
    try {
      if (await api.autolockCheck()) {
        state.unlocked = false;
        // 和 doLock 保持一致：条目列表里是名称/账号/网址明文，一起清掉
        state.items = [];
        state.selected = null;
        state.full.clear();
        state.shown.clear();
        state.secret.clear();
        swapScreen(() => renderLock("闲置超时，已自动锁定", true));
        return;
      }
      const st = await api.status();
      state.seconds = st.seconds_until_lock;
      const el = document.querySelector(".cd");
      if (el) el.textContent = countdown(st.seconds_until_lock);
    } catch {
      /* ignore */
    }
  }, 4000);

  try {
    // 浏览器预览：?screen=lock 直接看锁屏，?screen=app 看主界面。
    // 调界面时不用来回解锁，两条视图都能单独打开。
    //
    // 只在开发构建里认这个参数。发布版忽略它 —— 一个能决定「显示哪个界面」的
    // URL 入口不该出现在成品里，哪怕后端 IPC 另有拦截。
    const forced = import.meta.env.DEV
      ? new URLSearchParams(location.search).get("screen")
      : null;
    if (forced === "lock") {
      renderLock();
    } else if (forced === "register") {
      renderRegister();
    } else if (!("__TAURI_INTERNALS__" in window) && forced !== "app") {
      await enter();
    } else {
      const st = await api.status();
      if (st.unlocked) await enter();
      else renderLock();
    }
  } catch {
    renderLock();
  }

  // 首屏已经渲染进 DOM，可以显示窗口了。
  //
  // 窗口在 Rust 侧是 `visible: false` 创建的 —— 否则用户会先看到
  // WebView2 的白底、再看到我们的界面。这里等两个 rAF 确认这一帧
  // 真的画出来了，再通知 Rust show()，第一眼就是成品。
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      void api.uiReady();
    });
  });
}

void boot();