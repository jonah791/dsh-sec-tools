/**
 * 渗透工具调用轨迹单测（跑 lib 产物）。
 *
 * 覆盖：脱敏 / 摘要 / **闸门分类**（与 `unsafeArg` / `validUrl` 真实返回值交叉验证）/ 路径 / 序列化 / 解析
 * + 正常与失败落盘 + **尸体测试**（不可写路径 → `false` 且不抛，且不改变返回值/异常传播）
 * + **隐私尸体测试**（口令/用户名/哈希原文/hydra form → 断言绝不出现在落盘行里）。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  appendTraceEntry,
  buildStamp,
  classifyBreak,
  collectSecrets,
  defaultTargetOf,
  errorOf,
  isGate,
  isSensitiveKey,
  mtimeOf,
  parseTraceEntries,
  readPackageVersion,
  readTraceEntries,
  resolveHome,
  safeTrace,
  scrub,
  secretsOfUrl,
  serializeTraceEntry,
  summarizeArgs,
  summarizeResult,
  summarizeUrl,
  summarizeValue,
  tracePath,
  tracedExecute,
  truncate,
} from '../lib/trace.js'
import { unsafeArg, validUrl, validTarget } from '../lib/commands.js'

const tmp = mkdtempSync(join(tmpdir(), 'sec-tools-trace-'))
const base = (entry) => ({
  atMs: 1_700_000_000_000,
  phase: 'end',
  tool: 'sec_nmap',
  build: '0.1.0@42',
  pid: 777,
  durationMs: 91_234,
  ok: true,
  ...entry,
})

test('resolveHome / tracePath：DSH_HOME 优先，路径锚定单一文件名', () => {
  assert.equal(resolveHome({ DSH_HOME: 'E:/alice/.dsh' }, '/home/x'), 'E:/alice/.dsh')
  assert.equal(resolveHome({ DSH_HOME: ' ' }, '/home/x'), join('/home/x', '.dsh'))
  assert.equal(tracePath('/h/.dsh'), join('/h/.dsh', 'sec-tools-trace.jsonl'))
})

test('isSensitiveKey：凭据/哈希/form 命中；业务键不误伤', () => {
  for (const key of ['pass', 'password', 'user', 'username', 'hash', 'hashFile', 'cookie',
    'token', 'authorization', 'secret', 'form']) {
    assert.equal(isSensitiveKey(key), true, key + ' 应判敏感')
  }
  for (const key of ['target', 'url', 'domain', 'ports', 'scanType', 'extra', 'mode', 'wordlist',
    'level', 'rate', 'threads', 'action', 'db', 'table', 'tune', 'agility', 'recursive']) {
    assert.equal(isSensitiveKey(key), false, key + ' 不应判敏感')
  }
})

test('secretsOfUrl（不去重，去重归 collectSecrets）/ collectSecrets / scrub', () => {
  assert.deepEqual(secretsOfUrl('http://u%20ser:p%40ss@host/x'), ['u ser', 'p@ss'])
  assert.deepEqual(secretsOfUrl('not a url'), [])
  const secrets = collectSecrets({ user: 'ab', pass: 'hunter2', hash: 'deadbeef', target: 'h', ports: '80' })
  assert.ok(secrets.includes('hunter2') && secrets.includes('ab') && secrets.includes('deadbeef'))
  assert.equal(secrets.includes('h'), false)
  assert.deepEqual(collectSecrets({ pass: 'abc', form: 'abcdef' }), ['abcdef', 'abc'])
  assert.equal(scrub('hydra -p hunter2 -l ab', ['hunter2', 'ab']), 'hydra -p [redacted] -l [redacted]')
  assert.equal(scrub('abc', ['']), 'abc')
})

test('summarizeValue / summarizeUrl / summarizeArgs：只记长度 + 剥凭据 + 封顶', () => {
  assert.equal(summarizeValue('pass', 'hunter2'), '<7 chars>')
  assert.equal(summarizeValue('hash', 'deadbeef'), '<8 chars>')
  assert.equal(summarizeValue('form', '/login.php:user=^USER^:x'), '<24 chars>')
  assert.equal(summarizeValue('target', 'scanme.nmap.org'), 'scanme.nmap.org')
  assert.equal(summarizeValue('ports', '80,443'), '80,443')
  assert.equal(summarizeValue('target', 'z'.repeat(200)).length, 81)
  assert.equal(summarizeValue('ports', undefined), '')
  assert.equal(summarizeUrl('http://user:pass@h/x.php?a=1'), 'h/x.php')
  assert.equal(summarizeUrl('nope'), '<unparsable-url>')
  assert.equal(summarizeArgs({ target: 'h', pass: 'hunter2', scanType: 'sV', level: undefined }),
    'target=h; pass=<7 chars>; scanType=sV')
  assert.equal(summarizeArgs(null), '')
  assert.ok(summarizeArgs({ target: 'z'.repeat(2000) }, 100).length <= 101)
  assert.equal(truncate('abcdef', 3), 'abc…')
})

test('summarizeResult / errorOf：量级投影（ok 取显式字段），不落正文', () => {
  assert.deepEqual(summarizeResult({ ok: true, error: null, result: 'abc', exitCode: 0, stderr: null, durationMs: 5 }),
    { ok: true, exitCode: 0, resultBytes: 3 })
  assert.deepEqual(summarizeResult({ ok: false, error: 'WSL 未安装 nmap', result: null, exitCode: null, stderr: null }),
    { ok: false })
  assert.deepEqual(summarizeResult({ ok: false, error: 'x', result: 'r', stderr: 'ss' }), { ok: false, resultBytes: 1, stderrBytes: 2 })
  assert.deepEqual(summarizeResult(null), { ok: true })
  assert.equal(errorOf({ error: 'boom' }), 'boom')
  assert.equal(errorOf('str'), '')
})

test('classifyBreak：闸门类与非闸门类分得清（可 grep 的断点分类）', () => {
  assert.equal(classifyBreak(''), 'empty')
  assert.equal(classifyBreak('WSL 未安装 nmap'), 'missing-tool')
  assert.equal(classifyBreak('哈希文件不存在（WSL 路径）: /x'), 'missing-file')
  assert.equal(classifyBreak('hashFile 必填（WSL 内路径）'), 'bad-args')
  assert.equal(classifyBreak('nmap 执行失败: err'), 'tool-exit')
  assert.equal(classifyBreak('莫名其妙'), 'other')
  assert.equal(isGate('gate/unsafe-arg'), true)
  assert.equal(isGate('tool-exit'), false)
})

test('判据单一真源：classifyBreak 与 commands.ts 真实闸门返回值同源（文案漂移即测试红）', () => {
  // 6 个「原样拼接」参数的真实拒绝样本
  for (const [name, hostile] of [['extra', '-O; rm -rf /'], ['scanType', 'sV|id'], ['ports', '80`id`'],
    ['mode', 'dir$(id)'], ['service', 'ssh; id']]) {
    const verdict = unsafeArg(hostile, name)
    assert.equal(typeof verdict, 'string', name + ' 应被闸门拒绝')
    assert.equal(classifyBreak(verdict), 'gate/unsafe-arg', name + ' 的拒绝文案未被识别为闸门类')
    assert.equal(isGate(classifyBreak(verdict)), true)
  }
  const badUrl = validUrl('http://h/x;id')
  assert.equal(badUrl.ok, false)
  assert.equal(classifyBreak(badUrl.error), 'gate/invalid-url')
  assert.equal(validTarget('h;id'), false)
  assert.equal(classifyBreak('target 格式无效'), 'gate/invalid-target')
  // 放行样本不得被误判为闸门
  assert.equal(unsafeArg('-O -A', 'extra'), null)
  assert.equal(unsafeArg(undefined, 'extra'), null)
})

test('defaultTargetOf：target → url（剥凭据）→ domain', () => {
  assert.equal(defaultTargetOf({ target: 'scanme.nmap.org', domain: 'x' }), 'scanme.nmap.org')
  assert.equal(defaultTargetOf({ url: 'http://u:p@h/a' }), 'h/a')
  assert.equal(defaultTargetOf({ domain: 'x.com' }), 'x.com')
  assert.equal(defaultTargetOf({}), undefined)
})

test('serializeTraceEntry：单行 + 键序固定 + 缺省字段不污染', () => {
  const line = serializeTraceEntry(base({}))
  assert.equal(line.includes('\n'), false)
  assert.deepEqual(Object.keys(JSON.parse(line)), ['atMs', 'phase', 'tool', 'build', 'pid', 'durationMs', 'ok'])
  const full = JSON.parse(serializeTraceEntry(base({
    target: 'h', args: 'a', exitCode: 0, resultBytes: 1, stderrBytes: 2, break: 'tool-exit', error: 'e',
  })))
  assert.deepEqual(Object.keys(full).slice(6), ['args', 'durationMs', 'ok', 'exitCode',
    'resultBytes', 'stderrBytes', 'break', 'error'])
})

test('parseTraceEntries：坏行/半行/空行/null/标量跳过；readTraceEntries 缺失/目录返回空', () => {
  const good = serializeTraceEntry(base({}))
  const text = ['', good, '  ', '{"atMs":1,"phase":"end"', '{"tool":"sec_nmap"}', 'null', '0', 'nope', '[]'].join('\n')
  const parsed = parseTraceEntries(text)
  assert.equal(parsed.length, 1)
  assert.equal(parsed[0].tool, 'sec_nmap')
  assert.deepEqual(readTraceEntries(join(tmp, 'nope', 'sec-tools-trace.jsonl')), [])
  assert.deepEqual(readTraceEntries(tmp), [])
})

test('appendTraceEntry：追加可回读（begin/end 两行 = 一次调用）', () => {
  const path = join(tmp, 'ok', 'sec-tools-trace.jsonl')
  assert.equal(appendTraceEntry(path, base({ phase: 'begin', durationMs: 0 })), true)
  assert.equal(appendTraceEntry(path, base({})), true)
  assert.deepEqual(readTraceEntries(path).map((e) => e.phase), ['begin', 'end'])
})

test('尸体测试：父路径是普通文件 → 返回 false 且不抛（观测不反噬调用）', () => {
  const blocker = join(tmp, 'blocker')
  writeFileSync(blocker, 'not a dir', 'utf8')
  assert.doesNotThrow(() => {
    assert.equal(appendTraceEntry(join(blocker, 'sec-tools-trace.jsonl'), base({})), false)
    assert.equal(safeTrace(base({}), { path: join(blocker, 'sec-tools-trace.jsonl'), now: 1, pid: 1 }), false)
  })
})

test('闸门可见性（本插件的核心观测事件）：被 unsafeArg 拒绝 → 独立 gate 阶段 + 无 exitCode', async () => {
  const path = join(tmp, 'gate', 'sec-tools-trace.jsonl')
  const hostile = unsafeArg('-O; rm -rf /', 'extra')
  const wrapped = tracedExecute({ tool: 'sec_nmap', build: 'b@1', path, pid: 3, now: () => 1 },
    async () => ({ ok: false, error: hostile, result: null, exitCode: null, stderr: null, durationMs: 0 }))
  await wrapped({ target: 'scanme.nmap.org', extra: '-O; rm -rf /' })
  const lines = readTraceEntries(path)
  assert.deepEqual(lines.map((e) => e.phase), ['begin', 'gate'])
  assert.equal(lines[1].break, 'gate/unsafe-arg')
  assert.equal(lines[1].ok, false)
  assert.equal(lines[1].exitCode, undefined) // 从未产生子进程
  assert.equal(lines[0].tool, 'sec_nmap')
  assert.equal(lines[0].target, 'scanme.nmap.org')
})

test('非闸门失败落 end（不进 gate）：工具未安装 → missing-tool', async () => {
  const path = join(tmp, 'nogate', 'sec-tools-trace.jsonl')
  const wrapped = tracedExecute({ tool: 'sec_hydra', build: 'b@1', path, pid: 3, now: () => 1 },
    async () => ({ ok: false, error: 'WSL 未安装 hydra', result: null, exitCode: null, stderr: null }))
  await wrapped({ target: 'h.example', service: 'ssh' })
  const lines = readTraceEntries(path)
  assert.deepEqual(lines.map((e) => e.phase), ['begin', 'end'])
  assert.equal(lines[1].break, 'missing-tool')
})

test('tracedExecute 正常路径：begin/end + 注入时钟耗时 + 结果量级 + 返回值逐字不变', async () => {
  const path = join(tmp, 'wrap', 'sec-tools-trace.jsonl')
  const times = [100, 100, 350, 350]
  const wrapped = tracedExecute({ tool: 'sec_nmap', build: 'b@1', path, pid: 9, now: () => times.shift() ?? 350 },
    async (a) => ({ ok: true, error: null, result: 'PORT 22 open', exitCode: 0, stderr: null, echo: a.target }))
  const result = await wrapped({ target: 'scanme.nmap.org', scanType: 'sV' })
  assert.deepEqual(result, { ok: true, error: null, result: 'PORT 22 open', exitCode: 0, stderr: null, echo: 'scanme.nmap.org' })
  const lines = readTraceEntries(path)
  assert.equal(lines[0].durationMs, 0)
  assert.equal(lines[0].args, 'target=scanme.nmap.org; scanType=sV')
  assert.equal(lines[1].durationMs, 250)
  assert.equal(lines[1].resultBytes, 12) // 'PORT 22 open' = 12 字节
  assert.equal(lines[1].exitCode, 0)
  assert.equal(lines[1].pid, 9)
})

test('tracedExecute 异常路径：异常原样重抛（同一对象）+ 落分类错误', async () => {
  const path = join(tmp, 'wrap-fail', 'sec-tools-trace.jsonl')
  const boom = new TypeError('spawn wsl.exe ENOENT')
  const wrapped = tracedExecute({ tool: 'sec_gobuster', build: 'b@1', path, pid: 9, now: () => 1 },
    async () => { throw boom })
  await assert.rejects(() => wrapped({ url: 'http://h/' }), (e) => e === boom)
  const lines = readTraceEntries(path)
  assert.deepEqual(lines.map((e) => e.phase), ['begin', 'end'])
  assert.equal(lines[1].ok, false)
  assert.match(lines[1].error, /^other: /)
})

test('隐私尸体测试：口令/用户名/哈希原文/hydra form 绝不出现在落盘行里', async () => {
  const path = join(tmp, 'privacy', 'sec-tools-trace.jsonl')
  const args = {
    target: 'db.example',
    service: 'http-post-form',
    user: 'alice-secret-user',
    pass: 'hunter2-must-not-land',
    hash: 'deadbeef-must-not-land',
    form: '/login.php:user=hunter2-must-not-land:Invalid',
    url: 'http://alice-secret-user:hunter2-must-not-land@db.example/x',
  }
  const wrapped = tracedExecute({ tool: 'sec_hydra', build: 'b@1', path, pid: 2, now: () => 1 },
    async () => ({ ok: false, error: 'hydra 执行失败: user=alice-secret-user pass=hunter2-must-not-land', result: null, exitCode: 255, stderr: null }))
  await wrapped(args)
  const raw = readFileSync(path, 'utf8')
  for (const secret of ['alice-secret-user', 'hunter2-must-not-land', 'deadbeef-must-not-land']) {
    assert.equal(raw.includes(secret), false, secret + ' 泄漏进了轨迹！')
  }
  assert.ok(raw.includes('pass=<21 chars>'))
  assert.ok(raw.includes('user=<17 chars>'))
  assert.ok(raw.includes('hash=<22 chars>'))
  assert.ok(raw.includes('form=<45 chars>'))
  assert.ok(raw.includes('url=db.example/x')) // url 剥掉凭据，保留目标
  assert.ok(raw.includes('target=db.example'))
})

test('构建自证：buildStamp/readPackageVersion/mtimeOf', () => {
  const root = join(tmp, 'pkg')
  mkdirSync(join(root, 'lib'), { recursive: true })
  writeFileSync(join(root, 'package.json'), JSON.stringify({ version: '0.1.0' }), 'utf8')
  const self = join(root, 'lib', 'index.js')
  writeFileSync(self, '// x', 'utf8')
  assert.equal(readPackageVersion(self), '0.1.0')
  assert.ok(mtimeOf(self) > 0)
  assert.equal(buildStamp(self, '0.1.0'), '0.1.0@' + String(mtimeOf(self)))
  assert.equal(buildStamp(join(root, 'missing.js'), ''), 'unknown@0')
})

test('tracedExecute 观测失败不反噬：不可写路径下返回值照常、不抛；摘要函数抛错也被吞', async () => {
  const blocker = join(tmp, 'blocker')
  const wrapped = tracedExecute({
    tool: 'sec_nmap', build: 'b@1', path: join(blocker, 'sec-tools-trace.jsonl'), now: () => 1,
    targetOf: () => { throw new Error('targetOf 崩了') },
  }, async () => ({ ok: true, result: 'rp', exitCode: 0 }))
  assert.deepEqual(await wrapped({ target: 'h' }), { ok: true, result: 'rp', exitCode: 0 })
})

test('cleanup', () => {
  rmSync(tmp, { recursive: true, force: true })
})
