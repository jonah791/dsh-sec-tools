# 语义文档：dsh-sec-tools（安全工具面封装）

> 能力名：dsh-sec-tools（插件导出 `name = 'dsh-sec-tools'`，`src/index.ts:27`）
> 主副本路径：`self-plugins/dsh-sec-tools/docs/semantic.md`（本文件）
> 实现落点：`self-plugins/dsh-sec-tools/src/index.ts`（工具注册 + 统一包装）· `src/wsl.ts`（WSL 子进程基础设施）· `src/recon.ts`（侦察面 6 工具）· `src/attack.ts`（利用面 3 工具）· `src/crack.ts`（密码面 2 工具）
> 版本 v0.1.0（`package.json`） · 2026-09-14 · 作者：爱丽丝 · 状态：**draft**
> 开发方式：语义文档优先（先写清「是什么/什么关系/怎么裁决」，再让实现逼近，最后用实践回修）

---

## 1 · 定位与反定位

**定位**：把 WSL 里成熟的渗透测试工具（nmap/masscan/gobuster/subfinder/whatweb/dnsrecon/sqlmap/nikto/hydra/hashcat/john）封装为 **11 个结构化 DSH 工具**——参数结构化传入、经 `wsl.exe` 在 WSL 内执行、输出结构化返回，使模型调用成熟工具而不是自己拼命令。

**反定位（本文不管什么）**：
- 不管侦察/利用原语本身（`dsh-red-team` 管原语、`dsh-exploit-kit` 管利用链；本插件只管「成熟工具调用」）
- 不管目标授权流程（授权判断归使用者；插件只在每个工具 `description` 内置 boundary 声明）
- 不管 WSL 环境本身（发行版/工具安装是环境前提；缺工具时工具返回明确错误）
- **不是沙箱，也不是授权机制**：它拦不住被调用工具的全部行为——只做参数级防注入与存在性预检

## 2 · 术语表

| 术语 | 含义 |
|------|------|
| spawnWsl | `src/wsl.ts:22`：把命令 base64 编码后经 echo <b64> \| base64 -d \| bash 执行（规避 `wsl.exe` 的 argv 重解析破坏） |
| 目标面分组 | 侦察面（recon，6）· 利用面（attack，3）· 密码面（crack，2） |
| `sq()` | `src/recon.ts:11`：单引号包裹并把 `'` 转义为 `'\''`（bash 内防注入） |
| 预检 | 调用工具前先 `toolExists()`（`wsl.ts:45`）/`fileExists()`（`recon.ts:33`），缺失即返回明确错误 |
| outcome | 统一返回字段：`ok / error / result / exitCode / stderr / durationMs`（`index.ts:65` `baseProps`） |
| enabled | 唯一配置字段（`index.ts:31`）：**仅控制就绪日志**，不影响工具注册 |

## 3 · 概念模型

```
模型 / 会话 ──调用 sec_* ──► execute（wrapExecute 包一层，index.ts:44）
                                └─ run*()（recon/attack/crack）
                                     ├─ 参数校验（validTarget / validUrl / sq）
                                     ├─ toolExists 预检 ──缺工具即返回 {ok:false,error:'WSL 未安装 X'}
                                     └─ spawnWsl(cmd, timeoutMs)  → wsl.exe -d Ubuntu -- bash -c "echo <b64> | base64 -d | bash"
返回 {ok,error,result,exitCode,stderr,durationMs} ──► output.schema 校验 ──► render 人类可读文本
```

不变量（invariants）：
1. **I1 传参不破**：命令一律走 base64 通道（`wsl.ts:24`），`$`/引号/多行不丢——不允许直接拼 `wsl.exe -- <cmd>` 的 argv
2. **I2 参数先校验后执行**：target/url/wordlist 路径在构命令前过校验（`validTarget`/`validUrl`/`sq`），拒绝含 shell 元字符的输入
3. **I3 返回无损**：`undefined` 统一置 `null`（`index.ts:48` 注释：`undefined` 会被 `JSON.stringify` 丢弃导致 schema 校验失败）
4. **I4 schema 严格**：`additionalProperties:false` + `ok` 必填；所有工具共享 `outSchema()`（`index.ts:69`）
5. **I5 失败必达**：`execute` 全程 `try/catch`，异常转 `{ok:false,error}` 返回，不抛出到调用方（`index.ts:57`）

## 4 · 契约

### 4.1 服务与配置
- 依赖：`inject = ['tools']`（`index.ts:28`）；配置 `Config = z.object({ enabled: z.boolean().default(true) })`（`index.ts:31`）
- 组合行：`.dsh/profiles/web/cordis.patch.yml:186`（`id: agent-sec-tools`，未写 `config` → `enabled=true`）
- WSL 目标发行版：**硬编码 `'Ubuntu'`**（`wsl.ts:27`）——源码中不存在 `wslDistro` 配置字段（`README.md:62` 的声明与实现不符，见 §9/§10）
- 超时档位：`DEFAULT_TIMEOUT = 120_000`、`LONG_TIMEOUT = 600_000`（`wsl.ts:51`）；实际默认值——nmap/masscan/gobuster/subfinder/whatweb/dnsrecon = 120s，sqlmap/nikto/hashcat/john = 600s，hydra = 300s

### 4.2 输出契约
`outSchema()` 字段：`ok`(boolean,必填) / `error` / `result` / `exitCode` / `stderr` / `durationMs`；`render`（`index.ts:36` `wrapRender`）在 `ok=false` 时只输出 `error`，否则输出 `result` + `[stderr]`(截 300 字) + `[exit N · Tms]`。

### 4.3 调用点清单 `[MUST]`

| 调用方 | 调用点（文件:符号） | 时机 |
|-------|------------------|------|
| cordis 组合层 | `.dsh/profiles/web/cordis.patch.yml:186`（`id: agent-sec-tools`） | web 启动装配 |
| 插件 | `src/index.ts:27` `name='dsh-sec-tools'` / `:28` `inject=['tools']` / `:31` `Config` | 装配与激活门 |
| 插件 | `src/index.ts:62` `apply()` → `:64` `reg()` × 11 → `ctx.tools.register(defineTool(...))` | apply 一次 |
| 模型 / 会话 | `sec_nmap` `:77`｜`sec_masscan` `:93`｜`sec_gobuster` `:106`｜`sec_subfinder` `:120`｜`sec_whatweb` `:133`｜`sec_dnsrecon` `:145`｜`sec_sqlmap` `:159`｜`sec_nikto` `:180`｜`sec_hydra` `:192`｜`sec_hashcat` `:216`｜`sec_john` `:235` | 每次调用 |
| 插件包装 | `src/index.ts:44` `wrapExecute` / `:36` `wrapRender` / `:69` `outSchema` | 每次工具调用 |
| 侦察面实现 | `src/recon.ts:51` `runNmap`｜`:74` `runMasscan`｜`:98` `runGobuster`｜`:122` `runSubfinder`｜`:142` `runWhatweb`｜`:162` `runDnsrecon` | 对应工具 execute |
| 利用面实现 | `src/attack.ts:31` `runSqlmap`｜`:60` `runNikto`｜`:94` `runHydra` | 对应工具 execute |
| 密码面实现 | `src/crack.ts:29` `runHashcat`｜`:55` `runJohn` | 对应工具 execute |
| 进程执行层 | `src/wsl.ts:22` `spawnWsl`（base64 通道）→ `wsl.exe -d Ubuntu -- bash -c` | 每次子进程 |
| 预检 | `src/wsl.ts:45` `toolExists` / `src/recon.ts:33` `fileExists`（john 前置） | 构命令后、执行前 |
| 参数校验 | `src/recon.ts:11` `sq` / `:16` `validUrl` / `:23` `validTarget` / `:28` `validWord` | 每次构命令前 |
| 日志 | `src/index.ts:63` `ctx.logger('sec-tools')` · `:248` 就绪自报「11 工具：6 侦察 + 3 利用 + 2 密码」 | apply |

### 4.4 自证轨迹契约（可维护性 S4 · 2026-09-14）

**落盘路径（单一真源）**：`<DSH_HOME>/sec-tools-trace.jsonl`，写入者是
`src/trace.ts:resolveHome()`（`DSH_HOME` → 回退 `homedir()/.dsh`）+ `tracePath(home)`。
**一行一阶段**（单行 JSON，`atMs` 单调），可 `tail` / `grep`。

**行 schema**（`src/trace.ts:TraceEntry`；固定键序 `serializeTraceEntry` 锁住）：

| 字段 | 类型 | 出现阶段 | 含义 |
|------|------|---------|------|
| `atMs` | number | 全部 | 写入时刻（ms epoch） |
| `phase` | `'begin' \| 'gate' \| 'end'` | 全部 | **阶段枚举**：一次调用恒为 `begin` →（`gate` **或** `end`） |
| `tool` | string | 全部 | 工具名（如 `sec_nmap`） |
| `build` | string | 全部 | `<package.version>@<lib/index.js mtime ms>`（Q1：线上跑的是哪个构建） |
| `pid` | number | 全部 | 进程 pid |
| `target` | string? | 全部 | `target` → `url`（结构化 host+path）→ `domain` |
| `args` | string? | `begin` | 关键参数摘要（脱敏；敏感键只记 `<N chars>`） |
| `durationMs` | number | 全部 | `begin`=0；其余=全程实耗（Q5） |
| `ok` | boolean? | `gate`/`end` | 工具返回值里显式的 `ok` |
| `exitCode` | number? | `end` | 子进程退出码（`gate` 行**恒缺省**——闸门在触碰 WSL 之前拒绝） |
| `resultBytes` / `stderrBytes` | number? | `end` | 量级（**不落正文**） |
| `break` | string? | `gate`/`end` | `classifyBreak()` 分类（仅 `ok=false` 时出现） |
| `error` | string? | `gate`/`end` | 分类前缀 + **已 `scrub`** 的截断 200 字符文本 |

**阶段枚举的语义（本插件最关键的一条）**：

- `gate` = **在触碰 WSL 之前**被闸门拒绝（`unsafeArg()` / `validUrl()` / `validTarget()`）。
  该行同时证明两件事：**防线拦下了什么**，以及**这一发没有产生任何子进程**（故无 `exitCode`）。
- `end` = 已进入执行路径的一切结局（成功、工具缺失、子进程非零退出、spawn 异常）。

**分类枚举**（`classifyBreak`，可 grep；`isGate()` 判是否 `gate/` 前缀）：

| 分类 | 触发文案（与 `src/commands.ts` 同源） | 触碰 WSL |
|------|------------------------------------|---------|
| `gate/unsafe-arg` | `含 shell 元字符` / `类型不符` | ✗ |
| `gate/invalid-url` | `url 需 http(s)://` / `url 含特殊字符` | ✗ |
| `gate/invalid-target` | `格式无效` | ✗ |
| `missing-tool` | `WSL 未安装` | ✓（toolExists 探测） |
| `missing-file` | `不存在` | ✓ |
| `bad-args` | `必填` / `需提供` | ✗（但非闸门类，仍落 `end`——它属于参数完备性，不是注入防线） |
| `tool-exit` | `执行失败` | ✓ |
| `empty` / `other` | 空错误 / 其余 | ? |

**判据单一真源（§5.22 规则 4）**：分类所依赖的文案与 `commands.ts` 的实际输出**由单测交叉验证**
（`tests/trace.test.mjs`「判据单一真源」：用 `unsafeArg()`/`validUrl()`/`validTarget()` 的**真实返回值**
喂 `classifyBreak`）——文案漂移会让测试红，而不是让防线静默失效。

**隐私红线**：`pass` / `password` / `user` / `username` / `hash` / `hashFile` / `cookie` / `token` /
`authorization` / `secret` / `form`（hydra 解析模板，**可能**内嵌字面凭据，从严）**只记 `<N chars>`**；
`url` 内嵌 `user:pass@` 由 `summarizeUrl` 结构性剥离；`error` 落盘前过 `scrub(text, secrets)`。
`target` / `url` / `domain` / `ports` / `scanType` / `extra` / `mode` / `wordlist` / `level` / `rate` 等
业务键**保留**（排障要看，非凭据）。

**调用点清单**：

| 调用方 | 调用点（文件:符号） | 时机 |
|-------|------------------|------|
| 单一切面 | `src/index.ts:apply` → `reg(tool)`（**12 个工具全部**经它注册，轨迹接线只此一处） | 挂载时注册 |
| 接线 | `src/index.ts:apply` → `tracedExecute({tool, build}, tool.execute)` | 每次调用 |
| 落盘 | `src/trace.ts:tracedExecute` → `safeTrace` → `appendTraceEntry`（吞错返回 bool） | 每次调用两行 |
| 读取 | `src/trace.ts:readTraceEntries`（坏行/半行/空行/缺失/目录 → 空数组） | 诊断时 |

## 5 · 边界与信任

- **能力边界 ≠ 沙箱**：本插件防的是参数注入（`sq` 包裹 + URL/target 白名单校验）与工具缺失（预检）；**不防**被调用工具自身的行为、不防误用授权范围。
- 不越界清单：不做目标可达性探测以外的信息收集（侦察面仅封装既有工具）｜不默认开启危险参数（sqlmap 的 `os-shell` 不在默认集，`extra` 走调用者自负）｜不落盘凭据（破解产出原样透出 stdout）｜仅限自有/授权/靶场环境（每个工具 `description` 内置 boundary 文案）。
- 失败面：工具未安装 → `{ok:false,error:'WSL 未安装 X'}`；参数非法 → 校验错误文本；执行失败但**有 stdout** → 判 `ok:true`（`if (!r.ok && !r.stdout)` 判据，保留部分结果）；spawn 异常/超时 → `exitCode=-1` 或 `null`，`stderr` 带错误文本；哈希文件不存在（john）→ 明确报错。坏数据一律「拒绝 + 报错」，无静默吞错分支。

## 6 · 与既有机制的关系

- **DSH 组合变更（AGENTS.md §5.11）**：改 `src/**` 属组合变更——构建产物 `lib/index.js` 新于 web 进程启动时，`preflight_check` 判「有未验证构建」并强制完整试运行。
- **命令准则（AGENTS.md §5.1）**：插件本身即「命令行默认走 WSL2」的工程化——`wsl.exe -d Ubuntu -- bash -c`，与主人定调的调用链一致。
- **与同族插件**：`dsh-red-team`（侦察原语）/ `dsh-exploit-kit`（利用原语）/ `dsh-cyber-range`（靶场）互补；`spawnWsl` 的 base64 通道设计来源即这两者的教训（`src/wsl.ts:4` 注释）。
- **预检与哨兵**：装配改动经哨兵协议（预检 → kill+重启 → 唤醒）。

## 7 · 可证伪验收清单

| # | 可证伪命题 | 证据（单测名/命令/日志行） | 状态 |
|---|-----------|------------------------------|------|
| A1 | 工具面恰为 11 个 `sec_*` 且分三面（6+3+2） | `rg -n "name: 'sec_" src/` → 11 命中（index.ts:77/93/106/120/133/145/159/180/192/216/235） | 已实测 |
| A2 | 命令经 base64 通道传递，不走 argv 直传 | 源码 `src/wsl.ts:24-27`：echo <b64> \| base64 -d \| bash | 已实测 |
| A3 | 无 shell 字符串拼接工具调用，参数一律 `sq()` 包裹 | 源码 `src/recon.ts:11` + 各 `run*` 的 `cmd` 构造 | 已实测 |
| A4 | URL/目标校验拒绝 shell 元字符与非法格式 | 源码 `src/recon.ts:16-25`（`validUrl` 以正则拒绝 shell 元字符：分号/竖线/与号/反引号/美元符/括号/尖括号/引号/反斜杠/空白；`validTarget` 要求 `^[a-zA-Z0-9.-]+$` 且含 `.` 且不以 `-` 开头） | 已实测 |
| A5 | 返回字段无损（`undefined` → `null`，过严格 schema） | 源码 `src/index.ts:44-60` + `outSchema`（`additionalProperties:false`） | 已实测 |
| A6 | 组合已挂载且无构建滞后 | `.dsh/plugin-boot.jsonl` 末行 `live[]` 含 `dsh-sec-tools`、`stale[]` 为空 | 已实测 |
| A7 | 本实例跑的就是当前构建 | `lib/index.js` mtime = 2026-08-25 22:21:18 ＜ web 进程启动 = 2026-09-14 10:05:47（`plugin-boot.jsonl` 末行 `processStartMs=1789351547742`） | 已实测 |
| A8 | 配置项 `wslDistro` 存在且可切发行版（README 声明） | **证伪**：`rg -n "wslDistro" src/` → 0 命中；`wsl.ts:27` 硬编码 `'Ubuntu'` | 已实测（证伪，见 §9/§10） |
| A9 | `enabled=false` 会禁用工具面（直觉预期） | **证伪**：`src/index.ts:247` 仅 `if (config.enabled) logger.info(...)`——工具照常注册 | 已实测（证伪，见 §10） |
| A10 | 缺工具时返回明确错误而非崩溃 | 在 WSL 内临时隐藏某工具（如 `PATH` 剔除）后调用对应 `sec_*`，应得 `{ok:false,error:'WSL 未安装 X'}` | 待验收 |
| A11 | 真实扫描可跑通并结构化返回 | 线上跑 `sec_nmap {target: 'scanme.nmap.org'}`：`ok=true`、`exitCode` 与 `result` 含端口列表、`durationMs>0` | 待验收 |
| A12 | 回归能力存在且绿 | `npm test`（= `node --test "tests/*.test.mjs"`，跑 `lib/` 产物）→ **20 pass / 0 fail** | ✅ 2026-09-14 |
| A13 | 受校验参数无法逃逸（A3 的离线版） | `tests/commands.test.mjs`：`sq()` 包裹 + 内部单引号转义；`buildNmapCmd({target:"a.com'; id; '"})` 断言转义形态 | ✅ 2026-09-14 |
| A14 | **原样拼接参数有闸门**（新增防线） | `unsafeArg()` 拦 `; | & \` $ ( ) { } < > " ' \` 与换行；放行合法多参数 `-O -A`；`runNmap/runGobuster/runMasscan/runSqlmap/runHydra` 的元字符输入在**触碰 WSL 之前**即被拒 | ✅ 2026-09-14 |
| A15 | 闸门时序：格式校验 → 元字符闸门 → 工具探测 | `tests/commands.test.mjs`「target 非法优先于元字符闸门」：`runNmap({target:'bad target', extra:'; id'})` → 报 `target 格式无效` | ✅ 2026-09-14 |
| A16 | **`hydra` 凭据不再重复拼接**（真缺陷修复） | 修复前 `buildHydraCmd({user:'u',pass:'p'})` = `hydra 'u':'p':'p'`（hydra 按首个冒号切分 ⇒ 密码成为 `p:p`，凭据永远不匹配）；修复后 = `hydra 'u':'p'`，单测锁住 | ✅ 2026-09-14 |
| A17 | **闸门可见性**：被 `unsafeArg` 拒绝的调用落**独立 `gate` 阶段**且无 `exitCode` | `tests/trace.test.mjs`「闸门可见性」：喂 `unsafeArg` 的真实拒绝文本 → 断言行序 `['begin','gate']`、`break='gate/unsafe-arg'`、`exitCode===undefined` | ✅ 2026-09-14 |
| A18 | 分类判据与闸门文案**同源**（不靠两处各自维护） | `tests/trace.test.mjs`「判据单一真源」：`unsafeArg()`/`validUrl()`/`validTarget()` 真实返回值 → `classifyBreak` 必须归到 `gate/*`；放行样本不得误判 | ✅ 2026-09-14 |
| A19 | 观测不反噬：不可写路径 → `false` 且不抛、返回值/异常传播不变 | `tests/trace.test.mjs`「尸体测试」「观测失败不反噬」「异常原样重抛（同一对象）」 | ✅ 2026-09-14 |
| A20 | 隐私红线：口令/用户名/哈希原文/hydra form **绝不出现在落盘行里** | `tests/trace.test.mjs` 隐私尸体测试：喂秘密参数 → 断言文件内搜不到，且 `pass=<N chars>`/`url=<host+path>` 出现 | ✅ 2026-09-14 |
| A21 | 回归能力扩充后仍绿 | `npm test` → **40 pass / 0 fail**（既有 20 + 轨迹 20） | ✅ 2026-09-14 |
| A22 | 线上自证（五问一条命令可答） | `tail -3 <DSH_HOME>/sec-tools-trace.jsonl` → `tool`+`build` / `target`+`args` / `ok`+`exitCode` / `durationMs` 一齐可见 | **待线上验收**（需一次真实工具调用） |

## 8 · 与实现的关系

- 主实现：`src/index.ts`（注册/包装/渲染）、`src/wsl.ts`（执行）、`src/commands.ts`（**纯层，零 IO**：`sq`/`validUrl`/`validTarget`/`validWord`/`hasShellMeta`/`unsafeArg` + 11 个 `build*Cmd` 命令构造器——2026-09-14 从三面实现中抽出）、`src/recon.ts`/`src/attack.ts`/`src/crack.ts`（三面实现：校验 → 工具探测 → 执行）；构建产物 `lib/*.js`（`tsc -p tsconfig.json`）。
- 测试：`tests/commands.test.mjs`（20 用例，离线跑 `lib/` 产物，不触碰 WSL/网络）。
- 同语义副本：无（本文件为唯一主副本）。
- 未实现/未验证部分显式标注：~~**无测试套件**~~ **已补（2026-09-14）**；A10/A11 属**真实执行**行为（依赖 WSL 内已装工具），仍需线上验收；`Config` 只有 `enabled` 且不影响注册（A9 已证伪，见 §10 U2）。
- **生效判据**：① 改代码后 `npm run build`，比对 `lib/index.js` 的 mtime 与 web 进程启动时刻（`.dsh/plugin-boot.jsonl` 末行 `processStartMs`）——产物晚于进程启动即证明**新代码未被加载**，需重启；② 组合自报 `plugin_boot_status` 的 `stale` 清单为空；③ 工具级：会话内 `sec_*` 可答（返回 `{ok,...}` 结构，而非「工具不存在」）即插件已激活；④ 行为级：`sec_nmap` 对已知目标返回实际端口输出。
- **回退**：① 代码回退 `git -C E:/alice/self-plugins/dsh-sec-tools revert <sha>` + 重新 `npm run build`，再经哨兵协议重启使新构建生效；② 版本回退按 package version（当前 `0.1.0`）；③ 结构性回退 `plugin_unmount`（插件名 `dsh-sec-tools`）——11 个工具从工具面消失，WSL 侧工具与已装环境不受影响；④ 单点应急：组合行里给 `config.enabled: false` **不能**关闭工具（见 A9 证伪），要停用只能走 `plugin_stop`/卸载。

## 9 · 实践修订记录

- **2026-09-14 · 自证轨迹层（可维护性 S4，零业务行为变更）**
  - **缺口**：12 个工具都经 WSL 执行外部渗透工具，却只有 `ctx.logger` 的 ready 行（宿主 logger **不落盘**）
    ⇒ 事后无法回答「哪一发被 `unsafeArg()` 闸门挡下、断在哪一级、stdout 多长、花了多久」。
  - **补的语义（新契约）**：新增 `src/trace.ts`（纯函数 + 薄 IO）+ `<DSH_HOME>/sec-tools-trace.jsonl`
    （`begin` → `gate`/`end`），契约与调用点清单见 §4.4；切面**只有一处**——
    `src/index.ts:apply` 的 `reg()`，不在 12 个 `execute` 里各改一遍。
  - **补的语义（本插件特有的观测点）**：**闸门拒绝具有独立阶段 `gate`**。
    理由：`unsafeArg()` 闸门是「在触碰 WSL 之前拒绝」的纵深防御（6 个原样拼接参数），
    **「闸门拒绝了什么」是防线是否真在工作的一手证据**——混进 `end` 里就再也不能一条 `grep` 证明防线活着。
    `gate` 行**恒无 `exitCode`**，这本身就是「没有产生子进程」的机器可读证据。
  - **补的语义（判据单一真源）**：`classifyBreak` 依赖的是 `commands.ts` 的错误文案——
    单测用 `unsafeArg()`/`validUrl()`/`validTarget()` 的**真实返回值**交叉验证，文案漂移即测试红。
  - **补的语义（隐私红线，此前无此约束）**：口令/用户名/哈希原文/cookie/token/hydra `form`
    **只记长度**；`url` 内嵌凭据**结构性剥离**；`error` 落盘前过 `scrub()`。
  - **行为变更清单**：**无**。工具签名/参数/schema/render 逐字不变；`tracedExecute` 只做「落两行 + 原样转发」，
    异常**原样重抛同一个对象**——由单测钉住。
  - **测试**：`tests/trace.test.mjs`（20 条）。全仓 20 → **40/40**。
  - **踩坑登记（给自己也给后来者）**：测试文件头注释里写 `**闸门分类**/路径` 时，
    `**` + `/` 拼出的 `*/` **提前闭合了块注释**，整个文件变成语法错（`SyntaxError: Unexpected token '**'`）
    ——注释里避免「星号紧跟斜杠」的写法。
  - **未决**：轨迹无轮转（见 §10 U7）。

（I3：每次事故/实践暴露的语义缺口当场回写）

- 2026-09-14 补课：本插件此前无语义文档（可维护性工程）
  - 语义**被确认**：11 工具三面划分、`inject=['tools']`、base64 通道、统一 outcome 七字段、失败判据 `!r.ok && !r.stdout`
  - 语义**被补充**：§4.1 补齐真实超时档位（120s / 300s / 600s）与「发行版硬编码 Ubuntu」这一实现事实；§5 失败面按源码逐条列出
  - 语义**被修正**：README「配置：`wslDistro` 默认 Ubuntu」**与实现不符**——源码无该字段且发行版硬编码（`wsl.ts:27`）；同时 `enabled` 的语义务必写清：它只是就绪日志开关，不是功能开关
  - 教训（同时回写技能 `semantic-doc-first`）：README 面向使用者、语义文档面向实现者——**两者的字段清单必须分别与源码核对**，不能互为依据

- **2026-09-14 可维护性补课（批次 W3）：命令构造抽纯 + 20 测试 + 修 hydra 凭据缺陷 + 新增元字符闸门**
  - 语义**被确认**：`sq()` 转义正确（`'` → `'\''`）；`validUrl`/`validTarget`/`validWord` 对非法输入返回 `{ok:false}`/`false` 而不抛错；A8 的 `wslDistro` 证伪复核通过（本插件源码 0 命中，`wsl.ts` 硬编码 Ubuntu）。
  - 语义**被补充**：命令构造器 `build*Cmd`（11 个）与校验原语一并抽出为 `src/commands.ts`——`recon.ts` 以 `export { … } from './commands.js'` 转出旧名字，**既有导入路径与签名不变**（attack/crack/index 无需改 import）。
  - 语义**被修正（真缺陷，先证伪后修）**：`hydra` 在 `user`+`pass` 同时给定时把密码拼两遍（`hydra 'u':'p':'p'`）；hydra 按首个冒号切分 ⇒ 密码成为 `p:p`，**凭据永远不匹配**（表现为「跑通了但没结果」，最易被误读为「密码确实错」）。修复：仅在未走 `user+pass` 分支时补密码段。
  - 语义**被修正（安全加固，防线新增）**：`nmap.extra` / `nmap.scanType` / `masscan.ports` / `gobuster.mode` / `sqlmap.extra` / `hydra.service` 六个参数**原样拼进命令行**（不加引号，为保持多参数展开语义）——意味着 `extra: '; id'` 之类可直接执行任意命令。新增 `hasShellMeta`/`unsafeArg` 闸门，在**触碰 WSL 之前**拒绝含 `; | & \` $ ( ) { } < > " ' \` 与换行的取值；不含空格，故合法多参数（如 `-O -A`）不受影响。
  - 语义**被修正（文档级）**：README 的「配置 `wslDistro`」仍未实现（§10 U1 保持开放）——本次**未改 README**（不在本批次写域），仅在此复核并保持证伪记录。
  - 教训：**「参数一律 sq() 包裹」这类安全断言必须逐参数核对**——A3 原写「参数一律 `sq()` 包裹」是**不成立**的（6 个参数原样拼接）；单测把「哪些参数有包裹、哪些靠闸门」逐条锁死后，这条断言才第一次成为事实。

## 10 · 未决问题

- **U1** `wslDistro` 缺位：是补实现（把发行版做成配置字段）还是修 README（写明硬编码 Ubuntu）？我倾向**补实现**（多发行版环境更稳），但需主人裁决是否需要。
- **U2** `enabled=false` 的语义歧义：直觉预期是「停用工具面」，实现只是关日志。是否需要把 `enabled` 接入注册门控，或改为 `logReadyOnly` 之类名副其实的字段名？
- **U3** 无单测：`sq`/`validUrl`/`validTarget`/命令构造是否抽成纯函数并配 `node --test` 离线用例（可在不碰 WSL 的前提下验证注入防护）？
  → **已闭环（2026-09-14）**：`src/commands.ts` + `tests/commands.test.mjs`（20 用例）；A12–A16 全绿。命令构造与校验现已可离线全量验证（runX 只剩接线）。
- **U5** 原样拼接参数的闸门是否够（本次新增登记）：`unsafeArg` 只挡元字符，不挡「合法但危险」的参数（如 `--os-shell`、`--script=*`、`-p-` 全端口）。是否需要白名单式参数校验？倾向：保持现闸门（防注入）+ 在工具 description 里显式声明「危险参数自担」，不在插件层做策略判断。
- **U6** `number` 参数未做运行时类型校验（本次新增登记）：`port`/`threads`/`level`/`risk`/`tune`/`agility` 若被传字符串（绕过工具 schema）会原样进命令行。倾向：与 U5 一并评估——若要挡，需在 runX 加 `Number.isInteger` 检查（`commands.ts` 已有位置）。
- **U4** 「有 stdout 即判成功」的失败判据（`!r.ok && !r.stdout`）会把部分失败当成功——是否改为暴露 `ok` 与 `exitCode` 双语义由调用者裁决？
  → **部分缓解（2026-09-14）**：轨迹 `end` 行**同时**落 `ok` 与 `exitCode`/`resultBytes`/`stderrBytes`，
  排障时可事后判定「这是真成功还是部分失败」。但**工具返回值本身未改**（本轮零行为变更），语义歧义仍存。
- **U7** 轨迹**无轮转/无上限**（2026-09-14 新增登记）：`sec-tools-trace.jsonl` 长期运行会单文件增长。
  倾向：本批 4 个插件统一在运维层处理（与 §5.22 既有轨迹同款），**未决**。
