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


<p align="center">
  <a href="https://github.com/jonah791/dsh-sec-tools"><img src="https://img.shields.io/badge/version-0.1.0-blue" alt="version"></a>
  <img src="https://img.shields.io/badge/License-MIT-green" alt="license">
  <img src="https://img.shields.io/badge/TypeScript-3178C6" alt="TypeScript">
</p>
> 安全工具面封装：把 WSL 成熟渗透工具封装为结构化 DSH 工具，窄而深可组合。
> DeepSeek Harness 自研插件 · v0.1.0

## 定位

把 WSL 环境里成熟的渗透测试工具（nmap / sqlmap / hashcat / gobuster 等）封装成 **结构化 DSH 工具**——模型通过工具面直接调用成熟工具，而不是自己拼命令。spawnWsl 模式：工具在 WSL 里执行，参数结构化传入，输出结构化返回。

## 功能特性

- **成熟工具封装**：nmap（端口/服务扫描）、sqlmap（SQL 注入自动化）、hashcat（哈希破解）、john（密码破解）、gobuster（目录/子域爆破）、hydra（在线密码爆破）、masscan（高速端口扫描）、nikto（Web 漏洞扫描）、subfinder（子域枚举）、whatweb（技术栈识别）、dnsrecon（DNS 枚举）
- **spawnWsl 模式**：经 WSL 执行，参数结构化传入、输出结构化返回（JSON）
- **窄而深**：每个工具一个 DSH 工具，参数按工具语义设计，可组合
- **授权边界**：仅限自有 / 授权 / 靶场环境（工具描述内置 boundary 声明）

## 安装

```bash
git clone https://github.com/jonah791/dsh-sec-tools.git self-plugins/dsh-sec-tools
cd self-plugins/dsh-sec-tools && pnpm install && pnpm build
```

挂载到 web profile。组合行 id：`agent-sec-tools`。

## 使用（工具面）

| 工具 | 用途 |
|------|------|
| `sec_nmap` | nmap 端口/服务版本扫描（sV/sS/sT/sC） |
| `sec_sqlmap` | sqlmap 自动化 SQL 注入（检测/枚举库表/导出） |
| `sec_hashcat` | hashcat 哈希破解（MD5/NTLM/bcrypt 等模式） |
| `sec_john` | john 密码破解（自动格式检测） |
| `sec_gobuster` | gobuster 目录/子域/虚拟主机爆破 |
| `sec_hydra` | hydra 在线密码爆破（ssh/ftp/rdp/http 等） |
| `sec_masscan` | masscan 高速端口扫描（大范围） |
| `sec_nikto` | nikto Web 漏洞扫描 |
| `sec_subfinder` | subfinder 被动/主动子域枚举 |
| `sec_whatweb` | whatweb 技术栈识别 |
| `sec_dnsrecon` | dnsrecon DNS 记录枚举 |

## 配置

| 字段 | 默认 | 说明 |
|------|------|------|
| `wslDistro` | Ubuntu | 目标 WSL 发行版 |

## 技术要点

- **spawnWsl 模式**：工具调用经 `wsl.exe -d <distro> -- <cmd>`，结构化参数注入
- **授权纪律**：全部工具仅限授权环境（自有资产 / 靶场 / 授权测试）
- 与 dsh-red-team（侦察原语）/ dsh-exploit-kit（利用原语）互补：sec-tools 管「成熟工具调用」

## License

MIT