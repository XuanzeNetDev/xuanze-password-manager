/**
 * 主题：暗色 / 亮色 / 跟随系统。
 *
 * 用 `data-theme` 挂在 <html> 上，CSS 变量在 `:root` 里定义两套。
 * 不引任何 UI 框架 —— 这个应用总共十来个控件，框架换来的是冷启动时间。
 */

export type Theme = "dark" | "light" | "auto";

const KEY = "xz.theme";

/** 读取用户偏好。 */
export function getTheme(): Theme {
  const saved = localStorage.getItem(KEY);
  if (saved === "dark" || saved === "light" || saved === "auto") return saved;
  return "auto";
}

/** 当前实际生效的主题（auto 时按系统偏好解算）。 */
export function resolvedTheme(): "dark" | "light" {
  const t = getTheme();
  if (t !== "auto") return t;
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

/** 应用主题。 */
export function applyTheme(theme: Theme = getTheme()): void {
  localStorage.setItem(KEY, theme);
  const effective = theme === "auto" ? resolvedTheme() : theme;
  document.documentElement.setAttribute("data-theme", effective);
  // 让原生控件（滚动条、输入框、日期选择器）也跟着走
  document.documentElement.style.colorScheme = effective;
}

/** 监听系统主题变化（auto 模式下跟随）。 */
export function watchSystemTheme(): void {
  const mq = window.matchMedia("(prefers-color-scheme: light)");
  const onChange = () => {
    if (getTheme() === "auto") applyTheme("auto");
  };
  if (typeof mq.addEventListener === "function") {
    mq.addEventListener("change", onChange);
  } else {
    // 老 WebView 兜底
    (mq as MediaQueryList & { addListener: (cb: () => void) => void }).addListener(onChange);
  }
}
