/**
 * 利用面工具封装：sqlmap / nikto / hydra
 *
 * 注意：这些是「授权测试」工具，仅限自有/授权/靶场环境。
 * 命令构造用单引号包裹参数防注入；危险参数（--os-shell 等）不默认开启。
 */

import { spawnWsl, toolExists, type WslResult } from './wsl.js'
import { sq, validTarget, validUrl } from './recon.js'

// ═══════════════ sqlmap ═══════════════

export interface SqlmapOptions {
  url: string
  /** 注入参数（如 id，缺省自动检测） */
  param?: string
  /** 数据：dbs 枚举库 / tables 枚举表 / dump 提取 / current-db 当前库 */
  action?: 'dbs' | 'tables' | 'dump' | 'current-db'
  /** 指定数据库名（tables/dump 时） */
  db?: string
  /** 指定表名（dump 时） */
  table?: string
  /** 风险/级别：--level 1-5 --risk 1-3 */
  level?: number
  risk?: number
  /** 额外参数（谨慎：不默认 os-shell） */
  extra?: string
  timeoutMs?: number
}

export async function runSqlmap(opts: SqlmapOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  const u = validUrl(opts.url)
  if (!u.ok) return { ok: false, error: u.error }
  if (!(await toolExists('sqlmap'))) return { ok: false, error: 'WSL 未安装 sqlmap' }
  const paramFlag = opts.param ? ` -p ${sq(opts.param)}` : ''
  const action = opts.action ?? 'dbs'
  const actionFlag = action === 'dbs' ? '--dbs'
    : action === 'current-db' ? '--current-db'
    : action === 'tables' ? (opts.db ? `-D ${sq(opts.db)} --tables` : '--tables')
    : action === 'dump' ? (opts.db && opts.table ? `-D ${sq(opts.db)} -T ${sq(opts.table)} --dump` : '--dump')
    : '--dbs'
  const lvl = opts.level ?? 1
  const rsk = opts.risk ?? 1
  const extraFlag = opts.extra ? ` ${opts.extra}` : ''
  const cmd = `sqlmap -u ${sq(opts.url)}${paramFlag} ${actionFlag} --batch --level ${lvl} --risk ${rsk}${extraFlag} 2>&1`
  const r: WslResult = await spawnWsl(cmd, opts.timeoutMs ?? 600_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `sqlmap 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}

// ═══════════════ nikto ═══════════════

export interface NiktoOptions {
  url: string
  /** 扫描调优：0(全)/1(感兴趣)/2(配置文件误报)… */
  tune?: number
  timeoutMs?: number
}

export async function runNikto(opts: NiktoOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  const u = validUrl(opts.url)
  if (!u.ok) return { ok: false, error: u.error }
  if (!(await toolExists('nikto'))) return { ok: false, error: 'WSL 未安装 nikto' }
  const tuneFlag = opts.tune ? ` -Tuning ${opts.tune}` : ''
  const cmd = `nikto -h ${sq(opts.url)}${tuneFlag} -nointeractive 2>&1`
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 600_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `nikto 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}

// ═══════════════ hydra ═══════════════

export interface HydraOptions {
  target: string
  /** 协议：ssh/ftp/http-post-form/rdp/mysql 等 */
  service: string
  /** 用户名（缺省用 userlist） */
  user?: string
  /** 密码（缺省用 passlist） */
  pass?: string
  /** 用户字典路径 */
  userlist?: string
  /** 密码字典路径 */
  passlist?: string
  /** 服务端口（缺省协议默认） */
  port?: number
  /** 线程数 */
  threads?: number
  /** http-post-form 的特殊格式（如 "/login.php:user=^USER^&pass=^PASS^:Invalid"） */
  form?: string
  timeoutMs?: number
}

export async function runHydra(opts: HydraOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  if (!validTarget(opts.target)) return { ok: false, error: 'target 格式无效' }
  if (!(await toolExists('hydra'))) return { ok: false, error: 'WSL 未安装 hydra' }
  const cred = opts.user && opts.pass
    ? `${sq(opts.user)}:${sq(opts.pass)}`
    : opts.user
    ? `${sq(opts.user)} `
    : opts.userlist ? `-L ${sq(opts.userlist)} ` : ''
  const passPart = opts.pass ? `:${sq(opts.pass)}` : opts.passlist ? ` -P ${sq(opts.passlist)}` : ''
  const portFlag = opts.port ? ` -s ${opts.port}` : ''
  const thrFlag = opts.threads ? ` -t ${opts.threads}` : ''
  // 处理 http-post-form 特殊协议（service 参数含 :// 形式）
  const servicePart = opts.form
    ? `http-post-form ${sq(opts.form)}`
    : `${opts.service}`
  const cmd = `hydra ${cred}${passPart}${portFlag}${thrFlag} -f ${sq(opts.target)} ${servicePart} 2>&1`
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 300_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `hydra 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}
