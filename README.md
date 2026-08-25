<!--
  DSH 插件生态公约声明（plugin-ecosystem-convention · 组合优先/声明清晰/兼容优先）
  purpose: 安全工具面封装：把 WSL 成熟渗透工具（nmap/sqlmap/hashcat 等）封装为结构化 DSH 工具，spawnWsl 模式，窄而深可组合
  inject: 'tools'
  tools: sec_*
  runtime: host-only
  envDeps: WSL Ubuntu + 渗透工具（nmap/sqlmap/hashcat 等）
  boundary: 仅限自有/授权/靶场环境
  compat: cordis ^4.0.1 / dsh-tools ^0.1.0-rc.6
-->
# dsh-sec-tools

安全工具面封装：把 WSL 成熟渗透工具（nmap/sqlmap/hashcat 等）封装为结构化 DSH 工具，spawnWsl 模式，窄而深可组合
