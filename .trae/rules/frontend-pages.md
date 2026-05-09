# Biubo-rust 前端 Pages 开发规则

## 项目概述
- 当前分支 `pages` 专用于 GitHub Pages 官方网站开发
- 技术栈: React 19 + TypeScript + Vite 8
- 网站部署在 GitHub Pages，域名为 `waf.yzy15.dpdns.org`

## 代码规范
1. 组件使用函数式组件 + Hooks
2. 所有组件使用 TypeScript 类型注解
3. 使用 CSS 变量管理主题样式
4. 图片资源放在 `public/assets/` 目录
5. 公共组件按功能拆分，保持单一职责

## 设计规范
1. 主题: 深色网络安全主题
2. 配色: 以 `#0a0b0f` 为主背景，`#00d4ff` 为强调色
3. 字体: Orbitron（标题）、Inter（正文）、JetBrains Mono（代码）
4. 动画: 使用 CSS 动画，避免过度使用 JS 动画
5. 响应式: 优先移动端设计，断点: 480px, 768px, 1024px

## 构建部署
1. 推送到 `pages` 分支触发自动部署
2. 构建输出目录: `dist/`
3. CNAME: `waf.yzy15.dpdns.org`
4. Vite base 设置为 `./`

## 组件命名
- 组件文件使用 PascalCase: `App.tsx`, `Navigation.tsx`
- 样式文件与组件同名: `App.css`
- 工具函数使用 camelCase

## 注意事项
- 不要修改 `master` 或 `dev` 分支的代码
- 保持 `public/assets/` 与主分支同步
- 每次修改后运行 `npm run build` 验证构建
