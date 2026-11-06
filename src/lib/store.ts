// CyberShield — data layer (localStorage).
// Di versi React ini tidak ada PHP/MySQL: browser menyimpan data di
// localStorage dengan skema dan data awal yang SAMA PERSIS dengan
// database.sql versi PHP, supaya angka dan perilakunya identik.

export type RuleAction = 'ALLOW' | 'BLOCK'
export type Decision = 'ALLOWED' | 'BLOCKED'

export interface FirewallRule {
  id: number
  rule_name: string
  source_ip: string
  dest_port: number
  protocol: string
  action: RuleAction
  is_active: number
  created_at: string
}

export interface SecurityLog {
  id: number
  event_time: string
  source_ip: string
  dest_port: number
  activity_type: string
  action_taken: Decision
  description: string
}

export interface BlacklistEntry {
  id: number
  ip_address: string
  reason: string
  added_at: string
}

const SEED_RULES: FirewallRule[] = [
  { id: 1, rule_name: 'Allow Web HTTP', source_ip: '*', dest_port: 80, protocol: 'TCP', action: 'ALLOW', is_active: 1, created_at: '2026-11-06 09:00:00' },
  { id: 2, rule_name: 'Allow Web HTTPS', source_ip: '*', dest_port: 443, protocol: 'TCP', action: 'ALLOW', is_active: 1, created_at: '2026-11-06 09:00:00' },
  { id: 3, rule_name: 'Allow DNS', source_ip: '*', dest_port: 53, protocol: 'UDP', action: 'ALLOW', is_active: 1, created_at: '2026-11-06 09:00:00' },
  { id: 4, rule_name: 'Allow Internal LAN', source_ip: '192.168.1.0/24', dest_port: 0, protocol: 'TCP', action: 'ALLOW', is_active: 1, created_at: '2026-11-06 09:00:00' },
  { id: 5, rule_name: 'Block Telnet', source_ip: '*', dest_port: 23, protocol: 'TCP', action: 'BLOCK', is_active: 1, created_at: '2026-11-06 09:00:00' },
  { id: 6, rule_name: 'Block Remote Desktop', source_ip: '*', dest_port: 3389, protocol: 'TCP', action: 'BLOCK', is_active: 1, created_at: '2026-11-06 09:00:00' },
  { id: 7, rule_name: 'Block Suspicious Host', source_ip: '203.0.113.45', dest_port: 0, protocol: 'TCP', action: 'BLOCK', is_active: 1, created_at: '2026-11-06 09:00:00' },
  { id: 8, rule_name: 'Block FTP Legacy', source_ip: '*', dest_port: 21, protocol: 'TCP', action: 'BLOCK', is_active: 0, created_at: '2026-11-06 09:00:00' },
]

const SEED_BLACKLIST: BlacklistEntry[] = [
  { id: 1, ip_address: '45.148.10.12', reason: 'Port scanning terdeteksi', added_at: '2026-11-06 09:00:00' },
  { id: 2, ip_address: '185.220.101.47', reason: 'Percobaan DDoS', added_at: '2026-11-06 09:00:00' },
  { id: 3, ip_address: '103.75.196.88', reason: 'Brute force SSH', added_at: '2026-11-06 09:00:00' },
  { id: 4, ip_address: '91.240.118.69', reason: 'Malware C2 server', added_at: '2026-11-06 09:00:00' },
]

const SEED_LOGS: Array<[string, number, string, Decision, string]> = [
  ['192.168.1.10', 443, 'Normal Traffic', 'ALLOWED', 'HTTPS request ke server web'],
  ['192.168.1.15', 80, 'Normal Traffic', 'ALLOWED', 'HTTP request ke server web'],
  ['45.148.10.12', 22, 'Port Scan', 'BLOCKED', 'IP ada di blacklist'],
  ['203.0.113.45', 3389, 'Brute Force', 'BLOCKED', 'Aturan Block Suspicious Host'],
  ['192.168.1.20', 53, 'Normal Traffic', 'ALLOWED', 'Query DNS'],
  ['185.220.101.47', 80, 'DDoS', 'BLOCKED', 'IP ada di blacklist'],
  ['192.168.1.10', 443, 'Normal Traffic', 'ALLOWED', 'HTTPS request ke server web'],
  ['103.75.196.88', 22, 'Brute Force', 'BLOCKED', 'IP ada di blacklist'],
  ['192.168.1.25', 443, 'Normal Traffic', 'ALLOWED', 'HTTPS request ke server web'],
  ['91.240.118.69', 4444, 'Malware', 'BLOCKED', 'IP ada di blacklist'],
  ['192.168.1.12', 80, 'Normal Traffic', 'ALLOWED', 'HTTP request ke server web'],
  ['198.51.100.23', 23, 'Port Scan', 'BLOCKED', 'Aturan Block Telnet (port 23)'],
]

function load<T>(key: string, seed: T): T {
  try {
    const raw = localStorage.getItem(key)
    if (raw) return JSON.parse(raw) as T
  } catch {
    /* abaikan, pakai seed */
  }
  const copy = JSON.parse(JSON.stringify(seed)) as T
  localStorage.setItem(key, JSON.stringify(copy))
  return copy
}

function save(key: string, value: unknown) {
  localStorage.setItem(key, JSON.stringify(value))
}

export function getRules(): FirewallRule[] {
  return load('cs_rules', SEED_RULES)
}
const SEED_LOG_OBJECTS: SecurityLog[] = SEED_LOGS.map((l, i) => ({
  id: i + 1,
  event_time: '2026-11-06 09:00:0' + (i % 10),
  source_ip: l[0],
  dest_port: l[1],
  activity_type: l[2],
  action_taken: l[3],
  description: l[4],
}))

export function getAllLogs(): SecurityLog[] {
  return load('cs_logs', SEED_LOG_OBJECTS)
}
export function getBlacklist(): BlacklistEntry[] {
  return load('cs_blacklist', SEED_BLACKLIST)
}

export function addLog(entry: Omit<SecurityLog, 'id' | 'event_time'>): SecurityLog {
  const all = getAllLogs()
  const log: SecurityLog = {
    ...entry,
    id: Math.max(0, ...all.map((l) => l.id)) + 1,
    event_time: new Date().toLocaleString('id-ID'),
  }
  save('cs_logs', [...all, log])
  return log
}

export function clearLogs() {
  save('cs_logs', [])
}

export function addRule(rule: Omit<FirewallRule, 'id' | 'created_at'>): FirewallRule {
  const rules = getRules()
  const created: FirewallRule = {
    ...rule,
    id: Math.max(0, ...rules.map((r) => r.id)) + 1,
    created_at: new Date().toLocaleString('id-ID'),
  }
  save('cs_rules', [...rules, created])
  return created
}

export function toggleRule(id: number): FirewallRule | undefined {
  const rules = getRules().map((r) => (r.id === id ? { ...r, is_active: r.is_active ? 0 : 1 } : r))
  save('cs_rules', rules)
  return rules.find((r) => r.id === id)
}

export function deleteRule(id: number) {
  save('cs_rules', getRules().filter((r) => r.id !== id))
}

export function addBlacklist(ip: string, reason: string): BlacklistEntry {
  const list = getBlacklist()
  if (list.some((b) => b.ip_address === ip)) throw new Error('IP sudah ada di blacklist.')
  const entry: BlacklistEntry = {
    id: Math.max(0, ...list.map((b) => b.id)) + 1,
    ip_address: ip,
    reason,
    added_at: new Date().toLocaleString('id-ID'),
  }
  save('cs_blacklist', [...list, entry])
  addLog({ source_ip: ip, dest_port: 0, activity_type: 'Blacklist', action_taken: 'BLOCKED', description: `IP ditambahkan ke blacklist: ${reason}` })
  return entry
}

export function removeBlacklist(id: number) {
  save('cs_blacklist', getBlacklist().filter((b) => b.id !== id))
}

export function isValidIpOrWildcard(ip: string): boolean {
  if (ip === '*' || ip === '0.0.0.0/0') return true
  if (ip.includes('/')) {
    const [base, mask] = ip.split('/')
    return isValidIp(base) && /^\d+$/.test(mask) && +mask >= 0 && +mask <= 32
  }
  return isValidIp(ip)
}

export function isValidIp(ip: string): boolean {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip)
  if (!m) return false
  return m.slice(1).every((o) => +o >= 0 && +o <= 255)
}

function cidrMatch(ip: string, cidr: string): boolean {
  if (!cidr.includes('/')) return false
  const [base, maskStr] = cidr.split('/')
  const mask = parseInt(maskStr, 10)
  const toLong = (s: string) => s.split('.').reduce((a, o) => (a << 8) + parseInt(o, 10), 0) >>> 0
  const maskLong = mask === 0 ? 0 : (0xffffffff << (32 - mask)) >>> 0
  return (toLong(ip) & maskLong) === (toLong(base) & maskLong)
}

// Penilaian paket — SAMA seperti api.php versi PHP:
// blacklist dulu, lalu aturan BLOCK didahulukan, lalu port spesifik
// sebelum port 0, baru urut id.
export function decide(ip: string, port: number, rules: FirewallRule[], blacklist: BlacklistEntry[]): { decision: Decision; reason: string } {
  if (blacklist.some((b) => b.ip_address === ip)) {
    return { decision: 'BLOCKED', reason: 'IP ada di blacklist' }
  }
  const sorted = [...rules].sort(
    (a, b) =>
      Number(b.action === 'BLOCK') - Number(a.action === 'BLOCK') ||
      Number(b.dest_port !== 0) - Number(a.dest_port !== 0) ||
      a.id - b.id,
  )
  for (const r of sorted) {
    if (r.is_active !== 1) continue
    const ipMatch = r.source_ip === '*' || r.source_ip === ip || cidrMatch(ip, r.source_ip)
    const portMatch = r.dest_port === 0 || r.dest_port === port
    if (ipMatch && portMatch) {
      return { decision: r.action === 'BLOCK' ? 'BLOCKED' : 'ALLOWED', reason: `Aturan: ${r.rule_name}` }
    }
  }
  return { decision: 'ALLOWED', reason: 'Tidak ada aturan blokir yang cocok' }
}
