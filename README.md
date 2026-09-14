<!--
  DSH 插件生态公约声明（plugin-ecosystem-convention · 组合优先/声明清晰/兼容优先）
  purpose: 安全工具面封装——把 WSL 里成熟的渗透工具（nmap/masscan/gobuster/subfinder/whatweb/dnsrecon/sqlmap/nikto/hydra/hashcat/john）封装为 11 个结构化 DSH 工具（6 侦察 + 3 利用 + 2 密码），参数结构化传入、经 wsl.exe 在 WSL 内执行、输出结构化返回；每次调用落一行轨迹（含闸门与中断分类）
  inject: 'tools'
  tools: sec_nmap,sec_masscan,sec_gobuster,sec_subfinder,sec_whatweb,sec_dnsrecon,sec_sqlmap,sec_nikto,sec_hydra,sec_hashcat,sec_john
  runtime: host-only（经 wsl.exe；命令经 base64 通道传递）
  envDeps: WSL(Ubuntu) + 被调工具本身（缺工具时返回明确错误，不崩）；**离线单测不需要它们**
  boundary: 只做参数级防注入与工具存在性预检；**不是沙箱、不是授权机制**——拦不住被调工具的全部行为；仅限自有/授权/靶场环境
  compat: cordis ^4.0.1 / schemastery ^3.18.1-rc.1 / dsh-tools ^0.1.0-rc.6
-->
# dsh-sec-tools

<p align="center">
  <a href="https://github.com/jonah791/dsh-sec-tools"><img src="https://img.shields.io/badge/version-0.1.1-blue" alt="version"></a>
  <img src="https://img.shields.io/badge/License-MIT-green" alt="license">
  <img src="https://img.shields.io/badge/TypeScript-3178C6" alt="TypeScript">
  <img src="https://img.shields.io/badge/tests-40%20passed-brightgreen" alt="tests">
</p>

**一句话**：把 WSL 里 11 个成熟渗透工具封成 11 个结构化 DSH 工具——模型按工具语义传参、在 WSL 内执行、拿结构化结果，而不是自己拼命令行。

**为什么值得用**：让模型自己拼 `nmap`/`sqlmap` 命令行，等价于**把 shell 注入权交给模型**——参数里的 `;`、`|`、反引号会直接成为命令。本插件把这条路径关掉：参数经单引号包裹 + 元字符闸门（在触碰 WSL **之前**拒绝），命令经 **base64 通道**传给 `bash`（绕开 `wsl.exe` 对 argv 的二次 join），每个工具先做存在性预检（缺工具返回明确错误而非崩），输出统一走严格 schema。代价是灵活性——危险参数（如全端口、`--os-shell`）不做策略判断，**由使用者自担**。

## 能力

11 个工具，三面：侦察 6 / 利用 3 / 密码 2。

| 面 | 工具 | 用途（工具描述要点，均含「仅限授权测试」声明） |
|----|------|------|
| 侦察 | `sec_nmap` | nmap 端口/服务扫描（WSL）：识别开放端口与服务版本。专业版扫描，比自写扫描全。参数：`target`(必填) / `ports`（缺省 `-F` 快速常见端口）/ `scanType`（`sV` 默认 / `sS` / `sT` / `sC`）/ `extra` |
| | `sec_masscan` | masscan 高速端口扫描（WSL）：超大批量端口快速探测（比 nmap 快百倍）。适合大范围扫描。参数：`target`(必填，IP/CIDR) / `ports` / `rate`（默认 1000 pps） |
| | `sec_gobuster` | gobuster 目录/子域爆破（WSL）：`dir`（默认）/`dns`/`vhost` 三模式 |
| | `sec_subfinder` | subfinder 被动/主动子域枚举 |
| | `sec_whatweb` | whatweb 技术栈识别 |
| | `sec_dnsrecon` | dnsrecon DNS 记录枚举 |
| 利用 | `sec_sqlmap` | sqlmap 自动化 SQL 注入（检测/枚举库表/导出） |
| | `sec_nikto` | nikto Web 漏洞扫描 |
| | `sec_hydra` | hydra 在线密码爆破（ssh/ftp/rdp/http 等） |
| 密码 | `sec_hashcat` | hashcat 哈希破解（MD5/NTLM/bcrypt 等模式） |
| | `sec_john` | john 密码破解（自动格式检测；执行前先查 hash 文件存在性） |

超时档位：侦察类与 `sec_whatweb` 等默认 **120s**；`sec_sqlmap` / `sec_nikto` / `sec_hashcat` / `sec_john` **600s**；`sec_hydra` **300s**。

## 快速开始

**1) 装依赖**（自研插件家园 `self-plugins/`，在目标 profile 的 `package.json` 加 link 依赖）：

```jsonc
"dsh-sec-tools": "link:<工作区>/self-plugins/dsh-sec-tools"
```

**2) 挂组合**（agent 预设行）：

```yaml
- insert:
    - id: agent-sec-tools
      name: dsh-sec-tools
      config:
        enabled: true
```

**3) 30 秒验证**（先确认环境，再打自己）：在 WSL 内确认目标工具已安装，然后对一个**自有 / 本机 / 靶场**目标调用一次

```
sec_nmap target="127.0.0.1" ports="1-100"
```

期望：`{ok:true, result:"…端口列表…", exitCode:0, durationMs>0}`；若该工具未安装，应得 `{ok:false, error:"WSL 未安装 nmap…"}`（**明确错误而非崩溃**）。缺工具时不要把它误判为「插件坏了」——这是 `toolExists` 预检的预期行为。

## 配置

| 项 | 默认 | 说明 |
|----|------|------|
| `enabled` | `true` | **仅控制装载时的「就绪」日志**（`logger.info`）。当前实现**不接入工具注册门控**：置 `false` 时 11 个工具仍照常注册（见 `docs/semantic.md` §10 U2） |

**发行版是硬编码的**：WSL 目标固定 `Ubuntu`（`src/wsl.ts`），源码中**不存在** `wslDistro` 之类的配置字段。多发行版环境需要改源码，或先把目标工具装进 Ubuntu（见 §10 U1）。

## 落盘与自证（出问题时先看这里）

**唯一持久产物**：`<DSH_HOME>/sec-tools-trace.jsonl`（append-only，一行一阶段，`atMs` 单调；`DSH_HOME` 缺省 `~/.dsh`）。**无轮转、无上限**（见 §10 U7）。

| 阶段 | 含义 |
|------|------|
| `begin` | 工具调用开始（落工具名、目标、参数摘要、`durationMs: 0`） |
| `gate` | **在触碰 WSL 之前被闸门拒绝**（格式校验失败 / 参数含 shell 元字符 / 工具未安装）——一次调用**恒为** `begin → (gate 或 end)` |
| `end` | 命令执行收尾（落 `ok` / `exitCode` / `resultBytes` / `stderrBytes` / 耗时） |

| 字段 | 语义 |
|------|------|
| `atMs` / `build` | 写入时刻 / `<version>@<模块 mtime ms>` |
| `tool` / `target` / `args` | 工具名 / 目标（脱敏）/ 参数摘要（白名单 + 截断） |
| `phase` / `break` | 阶段枚举 / **中断分类**（`gate` 行的拒绝原因分类） |
| `ok` / `exitCode` / `resultBytes` / `stderrBytes` | 成功语义与输出体量（排障时可事后判定「真成功还是部分失败」） |
| `durationMs` | 每次调用实耗 |

**一条命令答五问**：

```bash
tail -3 "$DSH_HOME/sec-tools-trace.jsonl"
# ① 线上跑的是哪个构建 → build = "<版本>@<模块 mtime ms>"
# ② 谁发起 / 打向谁     → tool + target + args（脱敏摘要）
# ③ 断在哪一段         → phase 枚举：gate（闸门拦住，未触碰 WSL）/ end（真跑完）；break 给出 gate 的分类
# ④ 结果质量           → ok + exitCode + resultBytes + stderrBytes（两者同落，可区分「有 stdout 的失败」）
# ⑤ 耗时与预算         → durationMs（配合该工具的超时档位 120s/300s/600s 判是否被超时截断）
```

## 生效判据与回退

**生效判据**（三选一）：
1. 行为级：11 个 `sec_*` 工具在工具面可调用，且非法入参被拒（`target` 含空白 → `target 格式无效`；`url` 非 http(s) → 对应格式错误；参数含 shell 元字符 → 被 `unsafeArg` 闸门拒绝）；
2. 轨迹级：`tail -1 "$DSH_HOME/sec-tools-trace.jsonl"` 的 `build` 里 mtime **等于** `lib/index.js` 的 mtime ⇒ 进程在跑当前构建；
3. 生态级：`plugin_boot_status`（`dsh-plugin-bootreport`）的 `live` 含 `dsh-sec-tools`、`stale` 为空 ⇒ 同上（机器化版本）。

> 注意：**重新构建 ≠ 生效**——产物 mtime 新只证明「构建过」，**进程启动时间必须晚于产物 mtime** 才算「在跑它」。缺这一条时不得宣称「已生效」。
> 另注意：**「有输出」≠「成功」**——工具的失败判据是 `!ok && !stdout`，部分失败会被当成成功；判成功请看轨迹 `end` 行的 `ok` + `exitCode`（§10 U4）。

**回退**：
- 源码级：`git -C self-plugins/dsh-sec-tools revert <commit>` → 重新构建 → 预检 → 重启；
- 组合级：预设里给 `agent-sec-tools` 行加 `disabled: true`（或移除该行）→ 哨兵重启（注意：给 `config.enabled` 置 `false` **不会**摘掉工具，见「配置」）；
- 运行期：无持久业务状态；轨迹文件可随时删除；被 WSL 工具自身写出的产物（如 hashcat potfile、sqlmap 输出目录）不由本插件管理。

## 测试

```bash
npm test        # = node --test "tests/*.test.mjs"（跑 lib/ 产物，与运行时同源）
```

**40 例离线测试**（40/40 通过）：

- `tests/commands.test.mjs`（20 例）——命令构造与闸门：`sq()` 单引号包裹 + 内部引号转义；**注入样本被拒**（含元字符的 target/extra/url 在触碰 WSL 前即被 `unsafeArg` 拦下）；**闸门时序**（格式校验优先于元字符闸门：`target` 非法 + `extra` 含元字符 → 报 `target 格式无效`）；合法多参数（如 `-O -A`）放行；`sec_hydra` 凭据拼接回归（修复前会把密码重复拼接导致凭据永不匹配，现已锁住）；
- `tests/trace.test.mjs`（20 例）——轨迹层：路径解析、序列化键序、坏行跳过、闸门分类，以及观测不反噬的尸体测试（不可写路径 → 返回 `false` 且不抛）。

**离线单测不需要 WSL、不需要 nmap/sqlmap/hashcat 等任何工具、不需要网络、不需要授权目标**——用例只跑纯函数（命令构造 + 校验 + 轨迹），不 spawn 任何进程。**但插件的真实功能需要它们**：运行时必须有 WSL(Ubuntu) 且目标工具已安装（缺工具返回明确错误），扫描类工具会真实出网打目标——请只对自有/授权/靶场目标使用。

## 设计要点

- **base64 命令通道**：`wsl.exe` 会把 `--` 之后的 argv 重新 join 成命令行字符串，期间 `$`/引号/转义/换行会被破坏。命令先 base64 编码，外层只传 `echo <b64> | base64 -d | bash`；base64 字符集不含空格/引号/`$`/换行，命令正文不接触 Windows 侧二次解析。**这条不变量不得下移**——改动执行链路时不得绕过它。
- **闸门顺序不可颠倒**：格式校验 → 元字符闸门 → 工具存在性预检 → 执行。先闸门后预检，保证「非法输入在触碰 WSL 之前就被拒」，不给 WSL 侧留下任何执行痕迹（轨迹里体现为 `begin → gate`）。
- **参数包裹而不是聪明解析**：所有传入值走 `sq()` 单引号包裹 + 内部引号转义；「原样拼接」的参数（如 `extra`）必须过 `unsafeArg()` 元字符闸门。**新增任何工具或参数时，这两条是准入条件**。
- **`undefined` 一律置 `null`**：输出走严格 schema（`additionalProperties:false`），`undefined` 字段会被 `JSON.stringify` 丢弃导致校验失败，故统一置 `null` 保证 JSON 无损。
- **闸门只挡注入，不挡「合法但危险」**：`unsafeArg` 拦元字符，但不拦全端口、`--os-shell` 这类语义危险参数——这是刻意的（插件层不做策略判断），代价由使用者自担（§10 U5/U6）。
- **`enabled` 名不副实**：它当前只控制就绪日志。**若要真正停用工具面，请用组合层的 `disabled: true`**，不要依赖这个字段（§10 U2）。
- **不是沙箱**：参数级防注入 + 存在性预检 ≠ 权限边界。插件拦不住被调工具的全部行为，也无法校验目标是否获授权。

### 合规红线（硬性）

- 仅用于**自有 / 明确授权**的系统与开源靶场；
- 不触碰未经授权的第三方系统；
- 首次验证请对 `127.0.0.1` 或自建靶场进行，不使用公网第三方站点做冒烟。

## 相关文档

| 文档 | 内容 |
|------|------|
| [`docs/semantic.md`](docs/semantic.md) | **权威契约**：定位与反定位、术语、契约（超时档位 + 输出契约 + 调用点清单 + 轨迹行 schema）、可证伪验收清单（A1–A16，含两条**证伪**记录）、未决问题（U1–U7） |
| [alice-digital-life](https://github.com/jonah791/alice-digital-life) | 本插件所属生态的中心索引（全部自研插件） |
| 技能 `cyber-range` / `windows-security-hardening` / `plugin-maintainability` | 靶场实战方法论、安全加固、可维护性工程（五问判据） |

## License

MIT © jonah791

---

本插件属于我的数字生命爱丽丝（[alice-digital-life](https://github.com/jonah791/alice-digital-life)）的 DSH 自研插件生态——**50 个插件**按生命/认知/感知/行动/通信/治理/呈现七层组织。
