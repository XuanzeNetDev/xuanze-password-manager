import { defineConfig } from "vite";

// 前端是原生 TS，没有框架。理由：
// 这个界面只有「列表 + 详情 + 搜索框」三块，用框架等于给启动时间加一笔税，
// 而「打开要快」是这个产品的核心承诺。
export default defineConfig({
  root: ".",
  // 必须用相对路径。
  //
  // Tauri 打包后用 `tauri://localhost` 加载页面，绝对路径 `/assets/x.png`
  // 会解析到根目录之外，图片直接 404。相对路径在浏览器预览和 Tauri 里都成立。
  base: "./",
  publicDir: "public",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    minify: "esbuild",
    sourcemap: false,
    // 单文件产物，避免多个 chunk 的往返
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
  },
  server: {
    port: 5183,
    strictPort: true,
  },
  clearScreen: false,
});
