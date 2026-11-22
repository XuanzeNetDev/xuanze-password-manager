/// <reference types="vite/client" />

// 让 TypeScript 认识图片 import（Vite 会把它们解析成 URL 字符串）
declare module "*.png" {
  const src: string;
  export default src;
}