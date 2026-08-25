/**
 * 侦察面工具封装：nmap / masscan / gobuster / subfinder / whatweb / dnsrecon
 *
 * 每个工具：参数校验 → 构造命令 → spawnWsl 执行 → 输出解析为结构化结果。
 * 命令构造必须用引号包裹参数（防注入），路径/主机名校验。
 */

import { spawnWsl, toolExists, type WslResult } from './wsl.js'

/** 参数安全：单引号包裹并转义（WSL bash 内） */
export function sq(v: string): string {
  return "'" + v.replace(/'/g, "'\\''") + "'"
}

/** URL 校验：http(s):// 开头 + 禁止 shell 特殊字符（纵深防御，不只靠 sq 包裹） */
export function validUrl(v: string): { ok: boolean; error?: string } {
  if (!/^https?:\/\//i.test(v)) return { ok: false, error: 'url 需 http(s):// 开头' }
  if (/[;|&`$(){}<>"\\\s]/.test(v)) return { ok: false, error: 'url 含特殊字符（禁止 ; | & ` $ 空格 等 shell 元字符）' }
  return { ok: true }
}

/** 校验目标 host 格式（域名/IP，防命令注入） */
export function validTarget(v: string): boolean {
  return /^[a-zA-Z0-9.-]+$/.test(v) && v.includes('.') && !v.startsWith('-')
}

/** 校验纯字母数字标识（如接口名） */
export function validWord(v: string): boolean {
  return /^[a-zA-Z0-9_-]+$/.test(v)
}

/** WSL 内文件存在性检查 */
export async function fileExists(path: string): Promise<boolean> {
  const r = await spawnWsl(`test -f ${sq(path)} && echo YES || echo NO`, 10000)
  return r.ok && r.stdout.trim() === 'YES'
}

// ═══════════════ nmap ═══════════════

export interface NmapOptions {
  target: string
  /** 端口规格：如 "80,443" / "1-1000" / 缺省 -p-（全端口太慢，默认常见端口） */
  ports?: string
  /** 扫描类型：-sS(syn)/-sT(connect)/-sV(版本) 组合 */
  scanType?: string
  /** 额外参数（如 -O 系统探测 / -A 全面） */
  extra?: string
  timeoutMs?: number
}

export async function runNmap(opts: NmapOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  if (!validTarget(opts.target)) return { ok: false, error: 'target 格式无效（需 域名/IP，无特殊字符）' }
  if (!(await toolExists('nmap'))) return { ok: false, error: 'WSL 未安装 nmap' }
  const portFlag = opts.ports ? `-p ${sq(opts.ports)}` : '-F' // -F = 快速常见端口
  const scanFlag = opts.scanType ? `-${opts.scanType.replace(/^-/, '')}` : '-sV'
  const extraFlag = opts.extra ? ` ${opts.extra}` : ''
  const cmd = `nmap ${scanFlag} ${portFlag}${extraFlag} --open ${sq(opts.target)} 2>&1`
  const r: WslResult = await spawnWsl(cmd, opts.timeoutMs ?? 120_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `nmap 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode, stderr: r.stderr }
  return { ok: true, result: r.stdout, exitCode: r.exitCode, stderr: r.stderr }
}

// ═══════════════ masscan ═══════════════

export interface MasscanOptions {
  target: string
  /** 端口范围（默认 1-1000） */
  ports?: string
  /** 速率 pps（默认 1000，太高易被检测） */
  rate?: number
  timeoutMs?: number
}

export async function runMasscan(opts: MasscanOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  if (!validTarget(opts.target)) return { ok: false, error: 'target 格式无效' }
  if (!(await toolExists('masscan'))) return { ok: false, error: 'WSL 未安装 masscan' }
  const ports = opts.ports ?? '1-1000'
  const rate = opts.rate ?? 1000
  const cmd = `masscan ${sq(opts.target)} -p${ports} --rate ${rate} 2>&1`
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 120_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `masscan 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}

// ═══════════════ gobuster ═══════════════

export interface GobusterOptions {
  url: string
  /** 模式：dir（目录）/ dns（子域）/ vhost */
  mode?: string
  /** wordlist 路径（缺省用内置常见字典） */
  wordlist?: string
  /** 扩展名（如 php,html，目录爆破时） */
  extensions?: string
  timeoutMs?: number
}

export async function runGobuster(opts: GobusterOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  const u = validUrl(opts.url)
  if (!u.ok) return { ok: false, error: u.error }
  if (!(await toolExists('gobuster'))) return { ok: false, error: 'WSL 未安装 gobuster' }
  const mode = opts.mode ?? 'dir'
  const wl = opts.wordlist ?? '/usr/share/wordlists/dirb/common.txt'
  const extFlag = opts.extensions ? ` -x ${sq(opts.extensions)}` : ''
  const cmd = `gobuster ${mode} -u ${sq(opts.url)} -w ${sq(wl)}${extFlag} -t 20 2>&1`
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 120_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `gobuster 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}

// ═══════════════ subfinder ═══════════════

export interface SubfinderOptions {
  domain: string
  /** 是否递归（默认 false） */
  recursive?: boolean
  /** 是否做主动（含 API 探测，默认 passive 仅证书日志） */
  active?: boolean
  timeoutMs?: number
}

export async function runSubfinder(opts: SubfinderOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  if (!validTarget(opts.domain)) return { ok: false, error: 'domain 格式无效' }
  if (!(await toolExists('subfinder'))) return { ok: false, error: 'WSL 未安装 subfinder' }
  const recFlag = opts.recursive ? ' -recursive' : ''
  const activeFlag = opts.active ? ' -active' : ''
  const cmd = `subfinder -d ${sq(opts.domain)}${recFlag}${activeFlag} -silent 2>&1`
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 120_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `subfinder 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}

// ═══════════════ whatweb ═══════════════

export interface WhatwebOptions {
  url: string
  /** 聚合模式（-a 3，默认） */
  agility?: number
  timeoutMs?: number
}

export async function runWhatweb(opts: WhatwebOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  const u = validUrl(opts.url)
  if (!u.ok) return { ok: false, error: u.error }
  if (!(await toolExists('whatweb'))) return { ok: false, error: 'WSL 未安装 whatweb' }
  const a = opts.agility ?? 3
  const cmd = `whatweb -a ${a} ${sq(opts.url)} 2>&1`
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 120_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `whatweb 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}

// ═══════════════ dnsrecon ═══════════════

export interface DnsreconOptions {
  domain: string
  /** 枚举类型：std(标准)/brt(爆破)/srv(服务记录) */
  type?: string
  timeoutMs?: number
}

export async function runDnsrecon(opts: DnsreconOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  if (!validTarget(opts.domain)) return { ok: false, error: 'domain 格式无效' }
  if (!(await toolExists('dnsrecon'))) return { ok: false, error: 'WSL 未安装 dnsrecon' }
  const type = opts.type ?? 'std'
  const cmd = `dnsrecon -d ${sq(opts.domain)} -t ${sq(type)} 2>&1`
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 120_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `dnsrecon 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}
