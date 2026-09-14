/**
 * dsh-sec-tools：安全工具面封装
 *
 * 把 WSL 成熟渗透工具封装为结构化 DSH 工具（spawnWsl 模式，base64 通道）：
 *  - 侦察面：sec_nmap / sec_masscan / sec_gobuster / sec_subfinder / sec_whatweb / sec_dnsrecon
 *  - 利用面：sec_sqlmap / sec_nikto / sec_hydra
 *  - 密码面：sec_hashcat / sec_john
 *
 * 设计原则（dsh-plugin-development §0）：
 *  - 窄而深：每工具一类成熟能力，输出结构化 + render 人类可读
 *  - 可组合：nmap 出端口 → sqlmap 打注入；subfinder 出子域 → gobuster 扫目录
 *  - 可观测：ok/error/exitCode/stderr + durationMs
 *  - 最小权限：仅限授权测试，边界声明在每个工具 description
 *  - 安全：命令参数单引号包裹防注入；工具先 toolExists 预检
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  runNmap, runMasscan, runGobuster, runSubfinder, runWhatweb, runDnsrecon,
} from './recon.js'
import { runSqlmap, runNikto, runHydra } from './attack.js'
import { runHashcat, runJohn } from './crack.js'
import { DEFAULT_TIMEOUT, LONG_TIMEOUT } from './wsl.js'
import { buildStamp, readPackageVersion, tracedExecute } from './trace.js'

export const name = 'dsh-sec-tools'
export const inject = ['tools'] as const

export interface Config { enabled: boolean }
export const Config = z.object({ enabled: z.boolean().default(true) })

type Any = any

/** 包装执行 + 统一 render */
const wrapRender = (_a: Any, v: Any) => {
  if (!v.ok) return [{ type: 'text', text: v.error ?? '执行失败' }]
  const lines = [(v.result ?? '').trim()]
  if (v.stderr) lines.push(`\n[stderr] ${String(v.stderr).slice(0, 300)}`)
  lines.push(`\n[exit ${v.exitCode ?? '?'} · ${v.durationMs ?? '?'}ms]`)
  return [{ type: 'text', text: lines.join('\n') }]
}

const wrapExecute = (fn: (args: Any) => Promise<Any>) => async (args: Any) => {
  try {
    const t0 = Date.now()
    const r = await fn(args)
    // undefined 字段 JSON.stringify 会丢弃 → lossless 校验失败；统一置 null（JSON 无损）
    return {
      ok: r.ok === true,
      error: r.error ?? null,
      result: r.result ?? null,
      exitCode: r.exitCode ?? null,
      stderr: r.stderr ?? null,
      durationMs: Date.now() - t0,
    }
  } catch (e: Any) {
    return { ok: false, error: String(e?.message ?? e), result: null, exitCode: null, stderr: null, durationMs: 0 }
  }
}

export function apply(ctx: Context, config: Config): void {
  const logger = ctx.logger('sec-tools')
  // ── 可维护性 S4：自证轨迹（`<DSH_HOME>/sec-tools-trace.jsonl`）────────────────
  // 单一切面：12 个工具**全部**经 `reg()` 注册，轨迹接线只在这一处落笔（漏一处即新缺陷）。
  // 工具内部的 `unsafeArg()` 闸门在触碰 WSL 之前拒绝 ⇒ 那些调用落 `gate` 阶段（防线的一手证据）。
  const HERE = dirname(fileURLToPath(import.meta.url))
  const SELF = join(HERE, 'index.js')
  const BUILD = buildStamp(SELF, readPackageVersion(SELF))
  const reg = (tool: Any) => ctx.tools.register(defineTool({
    ...tool,
    execute: tracedExecute({ tool: String(tool.name), build: BUILD }, tool.execute as (a: Any) => Promise<Any>),
  }))
  const baseProps: Record<string, Any> = {
    ok: { type: 'boolean', required: true }, error: { type: 'string' }, result: { type: 'string' },
    exitCode: { type: 'number' }, stderr: { type: 'string' }, durationMs: { type: 'number' },
  }
  const outSchema = (extra: Record<string, Any> = {}) => ({
    type: 'object', additionalProperties: false,
    properties: { ...baseProps, ...extra },
  })

  /* ══════════ 侦察面 ══════════ */

  reg({
    name: 'sec_nmap',
    description: 'nmap 端口/服务扫描（WSL）：识别开放端口与服务版本。专业版扫描，比自写扫描全。仅限授权测试。',
    parameters: {
      target: { type: 'string', required: true, description: '目标主机（域名/IP，如 scanme.nmap.org）' },
      ports: { type: 'string', description: '端口规格："80,443" / "1-1000"（缺省 -F 快速常见端口）' },
      scanType: { type: 'string', description: '扫描类型：sV(版本，默认)/sS(syn)/sT(connect)/sC(脚本)' },
      extra: { type: 'string', description: '额外参数（如 -O 系统探测 / -A 全面）' },
      timeoutMs: { type: 'number', description: `超时 ms（默认 ${DEFAULT_TIMEOUT}）` },
    },
    output: { schema: outSchema(), render: wrapRender },
    execute: wrapExecute(async (a: Any) => runNmap({
      target: String(a.target), ports: a.ports, scanType: a.scanType, extra: a.extra, timeoutMs: a.timeoutMs,
    })),
  })

  reg({
    name: 'sec_masscan',
    description: 'masscan 高速端口扫描（WSL）：超大批量端口快速探测（比 nmap 快百倍）。适合大范围扫描。仅限授权测试。',
    parameters: {
      target: { type: 'string', required: true, description: '目标（IP/CIDR）' },
      ports: { type: 'string', description: '端口范围（默认 1-1000，可 "0-65535"）' },
      rate: { type: 'number', description: '速率 pps（默认 1000，太高易被检测）' },
      timeoutMs: { type: 'number', description: `超时 ms（默认 ${DEFAULT_TIMEOUT}）` },
    },
    output: { schema: outSchema(), render: wrapRender },
    execute: wrapExecute(async (a: Any) => runMasscan({ target: String(a.target), ports: a.ports, rate: a.rate, timeoutMs: a.timeoutMs })),
  })

  reg({
    name: 'sec_gobuster',
    description: 'gobuster 目录/子域爆破（WSL）：Web 目录枚举（dir 模式）/子域爆破（dns 模式）/虚拟主机（vhost）。仅限授权测试。',
    parameters: {
      url: { type: 'string', required: true, description: '目标 URL（dir 模式，如 http://x.com/）' },
      mode: { type: 'string', description: 'dir(默认)/dns/vhost' },
      wordlist: { type: 'string', description: '字典路径（缺省 /usr/share/wordlists/dirb/common.txt）' },
      extensions: { type: 'string', description: '扩展名（如 php,html）' },
      timeoutMs: { type: 'number', description: `超时 ms（默认 ${DEFAULT_TIMEOUT}）` },
    },
    output: { schema: outSchema(), render: wrapRender },
    execute: wrapExecute(async (a: Any) => runGobuster({ url: String(a.url), mode: a.mode, wordlist: a.wordlist, extensions: a.extensions, timeoutMs: a.timeoutMs })),
  })

  reg({
    name: 'sec_subfinder',
    description: 'subfinder 子域名枚举（WSL）：被动证书日志 + 可选主动 API 探测，输出子域列表。比 crt.sh 快且全。仅限授权测试。',
    parameters: {
      domain: { type: 'string', required: true, description: '目标域名' },
      recursive: { type: 'boolean', description: '递归枚举（默认 false）' },
      active: { type: 'boolean', description: '主动探测含 API（默认 passive）' },
      timeoutMs: { type: 'number', description: `超时 ms（默认 ${DEFAULT_TIMEOUT}）` },
    },
    output: { schema: outSchema(), render: wrapRender },
    execute: wrapExecute(async (a: Any) => runSubfinder({ domain: String(a.domain), recursive: a.recursive, active: a.active, timeoutMs: a.timeoutMs })),
  })

  reg({
    name: 'sec_whatweb',
    description: 'whatweb Web 技术栈识别（WSL）：比自写指纹更全（CMS/框架/中间件/JS 库）。仅限授权测试。',
    parameters: {
      url: { type: 'string', required: true, description: '目标 URL' },
      agility: { type: 'number', description: '聚合级别（默认 3）' },
      timeoutMs: { type: 'number', description: `超时 ms（默认 ${DEFAULT_TIMEOUT}）` },
    },
    output: { schema: outSchema(), render: wrapRender },
    execute: wrapExecute(async (a: Any) => runWhatweb({ url: String(a.url), agility: a.agility, timeoutMs: a.timeoutMs })),
  })

  reg({
    name: 'sec_dnsrecon',
    description: 'dnsrecon DNS 记录枚举（WSL）：A/NS/MX/SOA/TXT + 区域传送测试 + 子域爆破。DNS 侦察。仅限授权测试。',
    parameters: {
      domain: { type: 'string', required: true, description: '目标域名' },
      type: { type: 'string', description: 'std(默认标准)/brt(爆破)/srv(服务记录)' },
      timeoutMs: { type: 'number', description: `超时 ms（默认 ${DEFAULT_TIMEOUT}）` },
    },
    output: { schema: outSchema(), render: wrapRender },
    execute: wrapExecute(async (a: Any) => runDnsrecon({ domain: String(a.domain), type: a.type, timeoutMs: a.timeoutMs })),
  })

  /* ══════════ 利用面 ══════════ */

  reg({
    name: 'sec_sqlmap',
    description: 'sqlmap 自动化 SQL 注入（WSL）：检测并提取数据库（dbs/tables/dump）。专业注入工具。仅限授权测试。',
    parameters: {
      url: { type: 'string', required: true, description: '目标 URL（含注入参数，如 http://x.com/item?id=1）' },
      param: { type: 'string', description: '指定注入参数（缺省自动检测）' },
      action: { type: 'string', description: 'dbs(默认枚举库)/current-db/tables(需 db)/dump(需 db+table)' },
      db: { type: 'string', description: '数据库名（tables/dump 时）' },
      table: { type: 'string', description: '表名（dump 时）' },
      level: { type: 'number', description: '检测级别 1-5（默认 1）' },
      risk: { type: 'number', description: '风险 1-3（默认 1）' },
      extra: { type: 'string', description: '额外参数（谨慎，不含 os-shell）' },
      timeoutMs: { type: 'number', description: `超时 ms（默认 ${LONG_TIMEOUT}）` },
    },
    output: { schema: outSchema(), render: wrapRender },
    execute: wrapExecute(async (a: Any) => runSqlmap({
      url: String(a.url), param: a.param, action: a.action, db: a.db, table: a.table,
      level: a.level, risk: a.risk, extra: a.extra, timeoutMs: a.timeoutMs,
    })),
  })

  reg({
    name: 'sec_nikto',
    description: 'nikto Web 漏洞扫描器（WSL）：检测危险文件/配置错误/已知漏洞。Web 攻击面扫描。仅限授权测试。',
    parameters: {
      url: { type: 'string', required: true, description: '目标 URL（如 http://x.com/）' },
      tune: { type: 'number', description: '扫描调优（0 全扫/1 感兴趣文件/2 配置误报…）' },
      timeoutMs: { type: 'number', description: `超时 ms（默认 ${LONG_TIMEOUT}）` },
    },
    output: { schema: outSchema(), render: wrapRender },
    execute: wrapExecute(async (a: Any) => runNikto({ url: String(a.url), tune: a.tune, timeoutMs: a.timeoutMs })),
  })

  reg({
    name: 'sec_hydra',
    description: 'hydra 在线密码爆破（WSL）：ssh/ftp/http-post-form/rdp/mysql 等协议弱口令测试。仅限授权测试。',
    parameters: {
      target: { type: 'string', required: true, description: '目标主机' },
      service: { type: 'string', required: true, description: '协议：ssh/ftp/rdp/mysql/http-post-form 等' },
      user: { type: 'string', description: '用户名（缺省需 userlist）' },
      pass: { type: 'string', description: '密码（缺省需 passlist）' },
      userlist: { type: 'string', description: '用户字典路径（WSL 内）' },
      passlist: { type: 'string', description: '密码字典路径（WSL 内）' },
      port: { type: 'number', description: '服务端口' },
      threads: { type: 'number', description: '线程数（默认 16）' },
      form: { type: 'string', description: 'http-post-form 格式（如 "/login.php:user=^USER^&pass=^PASS^:Invalid"）' },
      timeoutMs: { type: 'number', description: `超时 ms（默认 300000）` },
    },
    output: { schema: outSchema(), render: wrapRender },
    execute: wrapExecute(async (a: Any) => runHydra({
      target: String(a.target), service: String(a.service), user: a.user, pass: a.pass,
      userlist: a.userlist, passlist: a.passlist, port: a.port, threads: a.threads, form: a.form, timeoutMs: a.timeoutMs,
    })),
  })

  /* ══════════ 密码面 ══════════ */

  reg({
    name: 'sec_hashcat',
    description: 'hashcat 哈希破解（WSL）：模式 0=MD5/1000=NTLM/3200=bcrypt/100=sha1/1400=sha256 等，字典或掩码攻击。注意 GPU 要求。仅限授权数据。',
    parameters: {
      hash: { type: 'string', description: '哈希值（单个）' },
      hashFile: { type: 'string', description: '哈希文件路径（WSL 内）' },
      mode: { type: 'number', required: true, description: 'hashcat 模式（0=MD5 1000=NTLM 3200=bcrypt 100=sha1 1400=sha256）' },
      attack: { type: 'number', description: '0=字典(默认) 3=掩码 6=字典+掩码' },
      wordlist: { type: 'string', description: '字典路径（缺省 rockyou.txt）' },
      mask: { type: 'string', description: '掩码（如 ?d?d?d?d）' },
      timeoutMs: { type: 'number', description: `超时 ms（默认 ${LONG_TIMEOUT}）` },
    },
    output: { schema: outSchema(), render: wrapRender },
    execute: wrapExecute(async (a: Any) => runHashcat({
      hash: a.hash, hashFile: a.hashFile, mode: Number(a.mode), attack: a.attack,
      wordlist: a.wordlist, mask: a.mask, timeoutMs: a.timeoutMs,
    })),
  })

  reg({
    name: 'sec_john',
    description: 'john 哈希破解（WSL）：通用密码破解，自动检测格式，支持字典/增量。CPU 友好。仅限授权数据。',
    parameters: {
      hashFile: { type: 'string', required: true, description: '哈希文件路径（WSL 内，john 格式）' },
      format: { type: 'string', description: '格式（如 raw-md5/nt/sha256crypt，缺省自动检测）' },
      wordlist: { type: 'string', description: '字典路径' },
      timeoutMs: { type: 'number', description: `超时 ms（默认 ${LONG_TIMEOUT}）` },
    },
    output: { schema: outSchema(), render: wrapRender },
    execute: wrapExecute(async (a: Any) => runJohn({ hashFile: String(a.hashFile), format: a.format, wordlist: a.wordlist, timeoutMs: a.timeoutMs })),
  })

  if (config.enabled) {
    logger.info('安全工具面就绪（11 工具：6 侦察 + 3 利用 + 2 密码，仅限授权测试）')
  }
}