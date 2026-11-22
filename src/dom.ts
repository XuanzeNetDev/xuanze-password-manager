/**
 * 极小的 DOM 构造工具。
 *
 * 为什么不 `innerHTML`：所有渲染内容里有用户数据（条目名、备注、标签），
 * 拼字符串等于给自己留 XSS 口子。这里的 `h()` 强制走 `textContent`。
 */

type Child = Node | string | number | null | undefined | false;

export interface Props {
  class?: string;
  id?: string;
  title?: string;
  type?: string;
  placeholder?: string;
  /** 图片地址。只在 <img> 上使用。 */
  src?: string;
  alt?: string;
  value?: string;
  htmlType?: string;
  disabled?: boolean;
  autofocus?: boolean;
  /** 事件：键名是事件名（不带 on），如 `click`、`input`。 */
  on?: Partial<Record<string, (ev: Event) => void>>;
  /** 直接设置属性的逃生口（dataset、aria-* 等）。 */
  attrs?: Record<string, string>;
}

/** 创建元素。 */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Props = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);

  if (props.class) el.className = props.class;
  if (props.id) el.id = props.id;
  if (props.title) el.title = props.title;
  if (props.placeholder !== undefined) {
    (el as HTMLInputElement).placeholder = props.placeholder;
  }
  if (props.value !== undefined) (el as HTMLInputElement).value = props.value;
  if (props.type) (el as HTMLInputElement).type = props.type;
  // 图片：src / alt 只对 <img> 有意义。
  // 只写进 Props 类型是不够的 —— 这里不赋值，元素上就什么都没有。
  if (props.src !== undefined) (el as HTMLImageElement).src = props.src;
  if (props.alt !== undefined) (el as HTMLImageElement).alt = props.alt;
  if (props.disabled) (el as HTMLButtonElement).disabled = true;
  if (props.autofocus) (el as HTMLInputElement).autofocus = true;

  if (props.attrs) {
    for (const [k, v] of Object.entries(props.attrs)) el.setAttribute(k, v);
  }
  if (props.on) {
    for (const [ev, fn] of Object.entries(props.on)) {
      if (fn) el.addEventListener(ev, fn);
    }
  }

  append(el, children);
  return el;
}

/** 批量追加子节点，过滤掉 null/undefined/false。 */
export function append(parent: Node, children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    parent.appendChild(typeof c === "object" ? c : document.createTextNode(String(c)));
  }
}

/** 清空并重填。 */
export function replaceChildren(parent: Element, children: Child[]): void {
  parent.textContent = "";
  append(parent, children);
}

/** 图标：用单个字符，省掉一整套 SVG 图标库的体积。 */
export function glyph(ch: string): HTMLSpanElement {
  return h("span", { class: "nav-glyph" }, ch);
}

/**
 * 内联 SVG 图标。
 *
 * 为什么不用图标字体或图标库：一个密码管理器需要的不超过十个图标，
 * 引一个 200KB 的库只为画十个线条毫无道理。这里每个图标都是
 * 一条 `path`，总共不到 2 KB。
 */
const ICONS: Record<string, string> = {
  // 加号
  plus: "M8 3v10M3 8h10",
  // 对勾
  check: "M3 8.5l3.2 3.2L13 5",
  // 下载（导出）
  download: "M8 2v8m0 0l-3-3m3 3l3-3M3 13h10",
  // 齿轮
  gear:
    "M8 5.6A2.4 2.4 0 1 0 8 10.4 2.4 2.4 0 0 0 8 5.6z" +
    "M8 1.6v1.6M8 12.8v1.6M2.7 2.7l1.1 1.1M12.2 12.2l1.1 1.1" +
    "M1.6 8h1.6M12.8 8h1.6M2.7 13.3l1.1-1.1M12.2 3.8l1.1-1.1",
  // 锁
  lock: "M4.5 7V5.2a3.5 3.5 0 0 1 7 0V7M3.4 7h9.2v6.2H3.4z",
  // 放大镜
  search: "M7.2 2.2a5 5 0 1 0 0 10 5 5 0 0 0 0-10zM10.9 10.9 14 14",
  // 眼睛（显示）
  eye: "M1.4 8s2.4-4.2 6.6-4.2S14.6 8 14.6 8s-2.4 4.2-6.6 4.2S1.4 8 1.4 8zM8 6.1a1.9 1.9 0 1 0 0 3.8 1.9 1.9 0 0 0 0-3.8z",
  // 划掉的眼睛（隐藏）
  eyeOff:
    "M6.2 3.9A7.6 7.6 0 0 1 8 3.8c4.2 0 6.6 4.2 6.6 4.2a12 12 0 0 1-2 2.4" +
    "M4.1 5.1A12 12 0 0 0 1.4 8s2.4 4.2 6.6 4.2c.9 0 1.7-.2 2.4-.5" +
    "M2.4 2.4l11.2 11.2",
  // 复制（两页纸）
  copy: "M5.6 5.6V2.8h7.6v7.6h-2.8M2.8 5.6h7.6v7.6H2.8z",
  // 导出（方框 + 右上箭头）
  export: "M9 2.4h4.6V7M13.4 2.6 7.6 8.4M11.4 9.4v3.2H3.4V4.6h3.2",
  // 太阳（切到亮色）
  sun:
    "M8 5.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z" +
    "M8 1v1.4M8 13.6V15M2.2 8h1.4M12.4 8H13.8" +
    "M3.9 3.9l1 1M11.1 11.1l1 1M12.1 3.9l-1 1M4.9 11.1l-1 1",
  // 导入（向下箭头进托盘）
  import: "M8 2v8m0 0l-3-3m3 3l3-3M3 11.5v1.5h10v-1.5",
  // 铅笔（编辑）
  pencil: "M11.2 2.4l2.4 2.4L5 13.4H2.6v-2.4zM9.8 3.8l2.4 2.4",
  // 月亮（切到暗色）
  moon: "M13.2 9.6A5.8 5.8 0 0 1 6.4 2.8 5.8 5.8 0 1 0 13.2 9.6z",
};

/** 造一个 16×16 的内联 SVG 图标。 */
export function icon(name: keyof typeof ICONS | string): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.5");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", ICONS[name] ?? ICONS.plus ?? "");
  svg.appendChild(path);
  return svg;
}

/** 时间戳 → 本地日期字符串。0 显示为「—」。 */
export function fmtDate(ts: number): string {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** 时间戳 → 相对时间（「3 天前」）。用于「最后使用」。 */
export function fmtRelative(ts: number, locale: string): string {
  if (!ts) return "—";
  const diff = Math.floor(Date.now() / 1000) - ts;
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ["year", 31536000],
    ["month", 2592000],
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60],
  ];
  for (const [unit, secs] of units) {
    if (Math.abs(diff) >= secs) return rtf.format(-Math.floor(diff / secs), unit);
  }
  return rtf.format(-diff, "second");
}
