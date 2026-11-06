import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity,
  Ban,
  CheckCircle2,
  LayoutDashboard,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Trash2,
} from 'lucide-react'
import {
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  addBlacklist,
  addLog,
  addRule,
  clearLogs,
  decide,
  deleteRule,
  getAllLogs,
  getBlacklist,
  getRules,
  isValidIp,
  isValidIpOrWildcard,
  removeBlacklist,
  toggleRule,
  type BlacklistEntry,
  type Decision,
  type FirewallRule,
  type SecurityLog,
} from '@/lib/store'

type View = 'dashboard' | 'firewall' | 'traffic' | 'logs' | 'blacklist'

const NORMAL_IPS = ['192.168.1.10', '192.168.1.15', '192.168.1.20', '192.168.1.25', '192.168.1.12', '10.0.0.5', '172.16.0.8']
const BAD_IPS = ['45.148.10.12', '185.220.101.47', '103.75.196.88', '91.240.118.69', '203.0.113.45', '198.51.100.23']
const NORMAL_PORTS = [80, 443, 443, 80, 53, 443, 8080]

const rand = <T,>(arr: T[]): T => arr[Math.floor(Math.random() * arr.length)]

const TITLES: Record<View, [string, string]> = {
  dashboard: ['Dashboard Monitoring', 'Ringkasan aktivitas jaringan secara real-time.'],
  firewall: ['Manajemen Aturan Firewall', 'Tambah, aktifkan, nonaktifkan, dan hapus aturan.'],
  traffic: ['Simulasi Traffic & Serangan', 'Jalankan traffic normal atau simulasi serangan.'],
  logs: ['Log Keamanan', 'Semua kejadian yang dicatat sistem.'],
  blacklist: ['Blacklist IP', 'Daftar IP yang selalu diblokir.'],
}

interface FeedItem {
  id: number
  time: string
  ip: string
  port: number
  type: string
  decision: Decision
  reason: string
}

interface ChartPoint {
  t: string
  allowed: number
  blocked: number
}

function DecisionBadge({ decision }: { decision: Decision }) {
  return decision === 'BLOCKED' ? (
    <Badge variant="danger">
      <Ban className="mr-1 h-3 w-3" /> BLOCKED
    </Badge>
  ) : (
    <Badge variant="success">
      <CheckCircle2 className="mr-1 h-3 w-3" /> ALLOWED
    </Badge>
  )
}

export default function App() {
  const [view, setView] = useState<View>('dashboard')
  const [rules, setRules] = useState<FirewallRule[]>(() => getRules())
  const [logs, setLogs] = useState<SecurityLog[]>(() => getAllLogs())
  const [blacklist, setBlacklist] = useState<BlacklistEntry[]>(() => getBlacklist())
  const [clock, setClock] = useState(() => new Date().toLocaleTimeString('id-ID'))
  const [running, setRunning] = useState(false)
  const [feed, setFeed] = useState<FeedItem[]>([])
  const [points, setPoints] = useState<ChartPoint[]>([])
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null)
  const [attack, setAttack] = useState<{ title: string; desc: string } | null>(null)
  const [ruleOpen, setRuleOpen] = useState(false)
  const [blOpen, setBlOpen] = useState(false)
  const [ruleSearch, setRuleSearch] = useState('')
  const [logSearch, setLogSearch] = useState('')
  const [logFilter, setLogFilter] = useState<'ALL' | Decision>('ALL')
  const [ruleForm, setRuleForm] = useState({ name: '', ip: '', port: '', protocol: 'TCP', action: 'ALLOW' })
  const [blForm, setBlForm] = useState({ ip: '', reason: '' })
  const timerRef = useRef<number | null>(null)
  const toastTimerRef = useRef<number | null>(null)
  const feedIdRef = useRef(0)

  const stats = useMemo(() => {
    const total = logs.length
    const allowed = logs.filter((l) => l.action_taken === 'ALLOWED').length
    const blocked = logs.filter((l) => l.action_taken === 'BLOCKED').length
    return { total, allowed, blocked, activeRules: rules.filter((r) => r.is_active === 1).length }
  }, [logs, rules])

  const refresh = () => {
    setRules(getRules())
    setLogs(getAllLogs())
    setBlacklist(getBlacklist())
  }

  const showToast = (msg: string, ok = true) => {
    setToast({ msg, ok })
    if (toastTimerRef.current) window.clearTimeout(toastTimerRef.current)
    toastTimerRef.current = window.setTimeout(() => setToast(null), 3500)
  }

  useEffect(() => {
    const t = window.setInterval(() => setClock(new Date().toLocaleTimeString('id-ID')), 1000)
    return () => window.clearInterval(t)
  }, [])

  useEffect(() => {
    return () => {
      if (timerRef.current) window.clearInterval(timerRef.current)
    }
  }, [])

  const sendPacket = (ip: string, port: number, type: string) => {
    const currentRules = getRules()
    const currentBl = getBlacklist()
    const d = decide(ip, port, currentRules, currentBl)
    const desc = d.decision === 'BLOCKED' ? d.reason : type === 'Normal Traffic' ? 'Request normal ke server' : d.reason
    addLog({ source_ip: ip, dest_port: port, activity_type: type, action_taken: d.decision, description: desc })
    refresh()
    feedIdRef.current += 1
    const item: FeedItem = { id: feedIdRef.current, time: new Date().toLocaleTimeString('id-ID'), ip, port, type, decision: d.decision, reason: d.reason }
    setFeed((prev) => [item, ...prev].slice(0, 30))
    setPoints((prev) => {
      const last = prev[prev.length - 1] ?? { t: '', allowed: 0, blocked: 0 }
      const next = [...prev, { t: item.time, allowed: last.allowed + (d.decision === 'ALLOWED' ? 1 : 0), blocked: last.blocked + (d.decision === 'BLOCKED' ? 1 : 0) }]
      return next.slice(-20)
    })
  }

  const generatePacket = () => {
    const isBad = Math.random() < 0.28
    const ip = isBad ? rand(BAD_IPS) : rand(NORMAL_IPS)
    const port = isBad ? rand([22, 23, 3389, 4444, 80, 1433]) : rand(NORMAL_PORTS)
    const type = isBad ? rand(['Port Scan', 'Brute Force', 'DDoS', 'Malware']) : 'Normal Traffic'
    sendPacket(ip, port, type)
  }

  const toggleTraffic = () => {
    if (running) {
      if (timerRef.current) window.clearInterval(timerRef.current)
      timerRef.current = null
      setRunning(false)
      showToast('Simulasi traffic dihentikan.')
    } else {
      timerRef.current = window.setInterval(generatePacket, 1500)
      setRunning(true)
      showToast('Simulasi traffic berjalan — paket baru tiap 1,5 detik.')
    }
  }

  const simulateAttack = async (kind: 'DDoS' | 'Port Scan' | 'SQL Injection' | 'Brute Force') => {
    const attacks = {
      DDoS: { ips: ['185.220.101.47', '45.148.10.12'], ports: [80, 443], n: 25, desc: 'DDoS flood: 25 paket dari 2 IP penyerang ke port 80/443.' },
      'Port Scan': { ips: ['45.148.10.12', '198.51.100.23'], ports: [21, 22, 23, 80, 443, 3389, 8080, 1433], n: 16, desc: 'Port scan: 16 percobaan ke banyak port dari IP mencurigakan.' },
      'SQL Injection': { ips: ['203.0.113.45', '91.240.118.69'], ports: [80, 443], n: 10, desc: 'SQL Injection: 10 percobaan injeksi ke aplikasi web (port 80/443).' },
      'Brute Force': { ips: ['103.75.196.88', '203.0.113.45'], ports: [22], n: 12, desc: 'Brute force SSH: 12 percobaan login ke port 22.' },
    } as const
    const a = attacks[kind]
    setAttack({ title: `Serangan ${kind} terdeteksi!`, desc: `${a.desc} Cek tabel Log Keamanan — paket dari IP blacklist / aturan BLOCK harus berstatus BLOCKED.` })
    for (let i = 0; i < a.n; i++) {
      sendPacket(rand([...a.ips]), rand([...a.ports]), kind)
      await new Promise((r) => setTimeout(r, 120))
    }
    showToast(`Simulasi ${kind} selesai — ${a.n} paket dicatat ke log.`)
  }

  const submitRule = () => {
    if (!ruleForm.name.trim() || !ruleForm.ip.trim()) return showToast('Nama aturan dan IP sumber wajib diisi.', false)
    if (!isValidIpOrWildcard(ruleForm.ip.trim())) return showToast('Format IP tidak valid. Gunakan IP, * , atau CIDR mis. 192.168.1.0/24', false)
    const port = ruleForm.port === '' ? 0 : parseInt(ruleForm.port, 10)
    if (Number.isNaN(port) || port < 0 || port > 65535) return showToast('Port harus 0-65535 (0 = semua port).', false)
    addRule({ rule_name: ruleForm.name.trim(), source_ip: ruleForm.ip.trim(), dest_port: port, protocol: ruleForm.protocol, action: ruleForm.action as 'ALLOW' | 'BLOCK', is_active: 1 })
    setRuleForm({ name: '', ip: '', port: '', protocol: 'TCP', action: 'ALLOW' })
    setRuleOpen(false)
    refresh()
    showToast('Aturan firewall berhasil ditambahkan.')
  }

  const submitBlacklist = () => {
    if (!isValidIp(blForm.ip.trim())) return showToast('Format IP tidak valid.', false)
    try {
      addBlacklist(blForm.ip.trim(), blForm.reason.trim() || 'Diblokir manual')
    } catch (e) {
      return showToast(e instanceof Error ? e.message : 'Gagal menambahkan IP.', false)
    }
    setBlForm({ ip: '', reason: '' })
    setBlOpen(false)
    refresh()
    showToast('IP ditambahkan ke blacklist.')
  }

  const filteredRules = rules.filter(
    (r) => !ruleSearch || (r.rule_name + r.source_ip + String(r.dest_port)).toLowerCase().includes(ruleSearch.toLowerCase()),
  )
  const filteredLogs = logs
    .slice()
    .reverse()
    .filter((l) => {
      if (logFilter !== 'ALL' && l.action_taken !== logFilter) return false
      if (!logSearch) return true
      const q = logSearch.toLowerCase()
      return (l.source_ip + l.activity_type + l.action_taken).toLowerCase().includes(q)
    })
    .slice(0, 100)
  const recentLogs = logs.slice(-6).reverse()

  const navItems: { id: View; label: string; icon: React.ReactNode; badge?: string }[] = [
    { id: 'dashboard', label: 'Dashboard Monitoring', icon: <LayoutDashboard className="h-4 w-4" /> },
    { id: 'firewall', label: 'Firewall Rules', icon: <Shield className="h-4 w-4" />, badge: `${stats.activeRules}/${rules.length}` },
    { id: 'traffic', label: 'Traffic & Simulasi', icon: <Activity className="h-4 w-4" /> },
    { id: 'logs', label: 'Log Keamanan', icon: <Search className="h-4 w-4" /> },
    { id: 'blacklist', label: 'Blacklist IP', icon: <Ban className="h-4 w-4" />, badge: String(blacklist.length) },
  ]

  return (
    <div className="flex min-h-screen bg-background">
      {/* Sidebar */}
      <aside className="hidden w-60 flex-none flex-col border-r bg-card p-4 md:flex">
        <div className="flex items-center gap-3 px-2 py-2">
          <div className="flex h-10 w-10 flex-none items-center justify-center rounded-xl bg-cyan-400">
            <ShieldCheck className="h-5 w-5 text-zinc-950" />
          </div>
          <div>
            <p className="text-[17px] font-black leading-none tracking-tight">
              CYBER<span className="text-cyan-400">SHIELD</span>
            </p>
            <p className="mt-1 text-[11px] text-muted-foreground">Network Security</p>
          </div>
        </div>
        <p className="mb-2 mt-6 px-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Menu</p>
        <nav className="space-y-1">
          {navItems.map((item) => (
            <Button
              key={item.id}
              variant={view === item.id ? 'secondary' : 'ghost'}
              className="w-full justify-start"
              onClick={() => setView(item.id)}
            >
              {item.icon}
              <span className="flex-1 text-left">{item.label}</span>
              {item.badge && <span className="rounded-full bg-muted px-2 py-0.5 text-xs">{item.badge}</span>}
            </Button>
          ))}
        </nav>
        <div className="mt-auto rounded-xl border p-3">
          <div className="flex items-center gap-2 text-sm font-semibold">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
            </span>
            Sistem Protected
          </div>
          <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">
            Firewall aktif. Semua trafik diperiksa terhadap aturan &amp; blacklist.
          </p>
          <p className="mt-2 font-mono text-[11px] text-muted-foreground">React + shadcn/ui • Vite • Vercel</p>
          <p className="font-mono text-[11px] text-muted-foreground">
            Muhamad Nabil Faiz Amrullah
            <br />
            242502040042 • 3TI01
          </p>
        </div>
      </aside>

      {/* Main */}
      <main className="min-w-0 flex-1 p-4 md:p-6">
        <header className="mb-5 flex flex-wrap items-center gap-3">
          <div className="flex min-w-[200px] flex-1 flex-col">
            <h1 className="text-xl font-bold tracking-tight md:text-2xl">{TITLES[view][0]}</h1>
            <p className="text-sm text-muted-foreground">{TITLES[view][1]}</p>
          </div>
          <Badge variant="success">● LIVE</Badge>
          <Badge variant="outline" className="font-mono">
            {clock}
          </Badge>
          <Button variant="destructive" onClick={() => simulateAttack('DDoS')}>
            <Siren className="h-4 w-4" /> Simulate Attack
          </Button>
        </header>

        {attack && (
          <Card className="mb-5 border-rose-500/50 bg-rose-500/10">
            <CardContent className="flex items-start gap-3 pt-6">
              <ShieldAlert className="h-6 w-6 flex-none text-rose-400" />
              <div className="flex-1">
                <p className="font-bold text-rose-300">{attack.title}</p>
                <p className="text-sm text-rose-200/80">{attack.desc}</p>
              </div>
              <Button variant="outline" size="sm" onClick={() => setAttack(null)}>
                Tutup
              </Button>
            </CardContent>
          </Card>
        )}

        {view === 'dashboard' && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
              <Card>
                <CardHeader className="pb-2">
                  <CardDescription>Total Paket Diperiksa</CardDescription>
                  <CardTitle className="text-3xl font-black">{stats.total.toLocaleString('id-ID')}</CardTitle>
                </CardHeader>
                <CardContent className="text-xs text-muted-foreground">Semua paket yang dicatat di log keamanan</CardContent>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardDescription>Koneksi Diizinkan</CardDescription>
                  <CardTitle className="text-3xl font-black text-emerald-400">{stats.allowed.toLocaleString('id-ID')}</CardTitle>
                </CardHeader>
                <CardContent className="text-xs text-muted-foreground">
                  {stats.total ? Math.round((stats.allowed / stats.total) * 100) : 0}% dari total paket
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardDescription>Ancaman Diblokir</CardDescription>
                  <CardTitle className="text-3xl font-black text-rose-400">{stats.blocked.toLocaleString('id-ID')}</CardTitle>
                </CardHeader>
                <CardContent className="text-xs text-muted-foreground">
                  {stats.total ? Math.round((stats.blocked / stats.total) * 100) : 0}% dari total paket
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardDescription>Aturan Firewall Aktif</CardDescription>
                  <CardTitle className="text-3xl font-black text-amber-400">{stats.activeRules}</CardTitle>
                </CardHeader>
                <CardContent className="text-xs text-muted-foreground">{rules.length} aturan total di database</CardContent>
              </Card>
            </div>

            <div className="grid gap-4 lg:grid-cols-3">
              <Card className="lg:col-span-2">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle>Traffic Jaringan (Live)</CardTitle>
                      <CardDescription>Paket diizinkan vs diblokir per simulasi</CardDescription>
                    </div>
                    <Badge variant={running ? 'success' : 'secondary'}>{running ? '● Running' : '⏸ Paused'}</Badge>
                  </div>
                </CardHeader>
                <CardContent className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={points.length ? points : [{ t: '—', allowed: 0, blocked: 0 }]}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                      <XAxis dataKey="t" tick={{ fontSize: 11 }} />
                      <YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
                      <Tooltip contentStyle={{ background: '#18181b', border: '1px solid #27272a', borderRadius: 8 }} />
                      <Line type="monotone" dataKey="allowed" stroke="#34d399" strokeWidth={2} dot={false} name="Allowed" />
                      <Line type="monotone" dataKey="blocked" stroke="#fb7185" strokeWidth={2} dot={false} name="Blocked" />
                    </LineChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>Allowed vs Blocked</CardTitle>
                  <CardDescription>Proporsi dari semua log keamanan</CardDescription>
                </CardHeader>
                <CardContent className="flex h-56 items-center justify-center">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={[{ name: 'Allowed', value: stats.allowed }, { name: 'Blocked', value: stats.blocked }]} dataKey="value" innerRadius={55} outerRadius={80} paddingAngle={2}>
                        <Cell fill="#34d399" />
                        <Cell fill="#f43f5e" />
                      </Pie>
                      <Tooltip contentStyle={{ background: '#18181b', border: '1px solid #27272a', borderRadius: 8 }} />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
                <CardContent className="flex justify-center gap-4 pt-0 text-xs">
                  <span>
                    <i className="mr-1 inline-block h-2.5 w-2.5 rounded-full bg-emerald-400" /> Allowed <b>{stats.allowed}</b>
                  </span>
                  <span>
                    <i className="mr-1 inline-block h-2.5 w-2.5 rounded-full bg-rose-500" /> Blocked <b>{stats.blocked}</b>
                  </span>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle>Log Keamanan Terbaru</CardTitle>
                <Button variant="outline" size="sm" onClick={() => setView('logs')}>
                  Lihat Semua →
                </Button>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Waktu</TableHead>
                      <TableHead>IP Sumber</TableHead>
                      <TableHead>Port</TableHead>
                      <TableHead>Aktivitas</TableHead>
                      <TableHead>Tindakan</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {recentLogs.map((l) => (
                      <TableRow key={l.id}>
                        <TableCell className="font-mono text-muted-foreground">{l.event_time}</TableCell>
                        <TableCell className="font-mono">{l.source_ip}</TableCell>
                        <TableCell className="font-mono">{l.dest_port}</TableCell>
                        <TableCell>{l.activity_type}</TableCell>
                        <TableCell>
                          <DecisionBadge decision={l.action_taken} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </div>
        )}

        {view === 'firewall' && (
          <Card>
            <CardHeader className="flex flex-row flex-wrap items-center gap-3 space-y-0">
              <div className="flex-1">
                <CardTitle>Manajemen Aturan Firewall</CardTitle>
                <CardDescription>Aktifkan / nonaktifkan aturan, atau tambah aturan baru. Aturan aktif langsung dipakai simulasi.</CardDescription>
              </div>
              <div className="relative">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input className="w-56 pl-8" placeholder="Cari aturan / IP..." value={ruleSearch} onChange={(e) => setRuleSearch(e.target.value)} />
              </div>
              <Dialog open={ruleOpen} onOpenChange={setRuleOpen}>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="h-4 w-4" /> Tambah Aturan
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Tambah Aturan Firewall</DialogTitle>
                    <DialogDescription>Aturan baru langsung aktif dan dipakai simulasi.</DialogDescription>
                  </DialogHeader>
                  <div className="space-y-3">
                    <div className="space-y-1.5">
                      <Label htmlFor="fName">Nama aturan</Label>
                      <Input id="fName" placeholder="Block Port 4444" value={ruleForm.name} onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })} />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="fIp">IP sumber</Label>
                      <Input id="fIp" className="font-mono" placeholder="192.168.1.50 atau *" value={ruleForm.ip} onChange={(e) => setRuleForm({ ...ruleForm, ip: e.target.value })} />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="space-y-1.5">
                        <Label htmlFor="fPort">Port (0 = semua)</Label>
                        <Input id="fPort" type="number" min={0} max={65535} placeholder="0" value={ruleForm.port} onChange={(e) => setRuleForm({ ...ruleForm, port: e.target.value })} />
                      </div>
                      <div className="space-y-1.5">
                        <Label htmlFor="fProto">Protokol</Label>
                        <select id="fProto" className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm" value={ruleForm.protocol} onChange={(e) => setRuleForm({ ...ruleForm, protocol: e.target.value })}>
                          <option>TCP</option>
                          <option>UDP</option>
                          <option>ANY</option>
                        </select>
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="fAction">Aksi</Label>
                      <select id="fAction" className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm" value={ruleForm.action} onChange={(e) => setRuleForm({ ...ruleForm, action: e.target.value })}>
                        <option value="ALLOW">ALLOW — Izinkan</option>
                        <option value="BLOCK">BLOCK — Blokir</option>
                      </select>
                    </div>
                    <Button className="w-full" onClick={submitRule}>
                      Simpan Aturan
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Aturan</TableHead>
                    <TableHead>IP Sumber</TableHead>
                    <TableHead>Port</TableHead>
                    <TableHead>Protokol</TableHead>
                    <TableHead>Aksi</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredRules.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="font-semibold">{r.rule_name}</TableCell>
                      <TableCell className="font-mono">{r.source_ip}</TableCell>
                      <TableCell className="font-mono">{r.dest_port === 0 ? 'All' : r.dest_port}</TableCell>
                      <TableCell>{r.protocol}</TableCell>
                      <TableCell>{r.action === 'BLOCK' ? <Badge variant="danger">BLOCK</Badge> : <Badge variant="success">ALLOW</Badge>}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Switch
                            checked={r.is_active === 1}
                            onCheckedChange={() => {
                              toggleRule(r.id)
                              refresh()
                              showToast(r.is_active === 1 ? 'Aturan dinonaktifkan.' : 'Aturan diaktifkan.')
                            }}
                          />
                          <span className={`text-xs ${r.is_active === 1 ? 'text-emerald-400' : 'text-muted-foreground'}`}>{r.is_active === 1 ? 'Aktif' : 'Nonaktif'}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => {
                            if (window.confirm('Hapus aturan ini?')) {
                              deleteRule(r.id)
                              refresh()
                              showToast('Aturan dihapus.')
                            }
                          }}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <p className="mt-3 text-xs text-muted-foreground">
                💡 Uji cepat: nonaktifkan aturan <b>Block Telnet</b>, lalu jalankan simulasi Port Scan ke port 23 — paketnya akan lolos (ALLOWED).
                Aktifkan lagi, paketnya diblokir.
              </p>
            </CardContent>
          </Card>
        )}

        {view === 'traffic' && (
          <div className="grid gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle>Simulasi Lalu Lintas Jaringan</CardTitle>
                <CardDescription>Setiap paket dicek ke blacklist + aturan firewall aktif, lalu dicatat ke log keamanan.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="flex flex-wrap gap-2">
                  <Button onClick={toggleTraffic}>{running ? '⏸ Hentikan Traffic' : '▶ Jalankan Traffic'}</Button>
                  <Button variant="outline" onClick={generatePacket}>
                    + 1 Paket Manual
                  </Button>
                  <Button variant="outline" onClick={() => setFeed([])}>
                    Bersihkan Feed
                  </Button>
                </div>
                <div>
                  <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Simulasi Serangan</p>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="destructive" onClick={() => simulateAttack('DDoS')}>
                      🌊 DDoS Flood
                    </Button>
                    <Button variant="destructive" onClick={() => simulateAttack('Port Scan')}>
                      🔍 Port Scan
                    </Button>
                    <Button variant="destructive" onClick={() => simulateAttack('SQL Injection')}>
                      💉 SQL Injection
                    </Button>
                    <Button variant="destructive" onClick={() => simulateAttack('Brute Force')}>
                      🔑 Brute Force SSH
                    </Button>
                  </div>
                </div>
                <div>
                  <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Live Feed <span className="normal-case">(paket terbaru di atas)</span></p>
                  <div className="max-h-96 space-y-2 overflow-y-auto font-mono text-[13px]">
                    {feed.length === 0 && <p className="text-muted-foreground">Belum ada paket. Klik “Jalankan Traffic” atau “Simulate Attack”.</p>}
                    {feed.map((f) => (
                      <div key={f.id} className="flex flex-wrap items-center gap-2 rounded-lg border bg-muted/40 px-3 py-2">
                        <span className="text-muted-foreground">{f.time}</span>
                        <span className="font-semibold">{f.ip}</span>
                        <span className="text-muted-foreground">:{f.port}</span>
                        <span className="text-muted-foreground">{f.type}</span>
                        <span className="ml-auto">
                          <DecisionBadge decision={f.decision} />
                        </span>
                        <span className="w-full text-xs text-muted-foreground">{f.reason}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="h-fit">
              <CardHeader>
                <CardTitle>Cara Kerja Penilaian</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm leading-relaxed text-muted-foreground">
                <p>1. Paket dicek dulu ke <b className="text-foreground">blacklist</b> → kalau IP ada di sana, langsung <span className="font-semibold text-rose-400">BLOCKED</span>.</p>
                <p>2. Lalu dicek ke <b className="text-foreground">aturan firewall</b> yang aktif → kalau cocok IP + port dengan aksi BLOCK, <span className="font-semibold text-rose-400">BLOCKED</span>.</p>
                <p>3. Kalau tidak ada yang cocok, <span className="font-semibold text-emerald-400">ALLOWED</span>.</p>
                <p>4. Setiap keputusan dicatat ke <b className="text-foreground">log keamanan</b>.</p>
                <div className="rounded-lg border bg-muted/40 p-3 font-mono text-xs leading-relaxed">
                  Contoh IP jahat:
                  <br />
                  45.148.10.12 (blacklist)
                  <br />
                  185.220.101.47 (DDoS)
                  <br />
                  203.0.113.45 (aturan BLOCK)
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {view === 'logs' && (
          <Card>
            <CardHeader className="flex flex-row flex-wrap items-center gap-3 space-y-0">
              <div className="flex-1">
                <CardTitle>Log Keamanan</CardTitle>
                <CardDescription>Waktu kejadian, IP sumber, port tujuan, jenis aktivitas, dan tindakan sistem.</CardDescription>
              </div>
              <div className="relative">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input className="w-56 pl-8" placeholder="Cari IP / aktivitas..." value={logSearch} onChange={(e) => setLogSearch(e.target.value)} />
              </div>
              <Tabs value={logFilter} onValueChange={(v) => setLogFilter(v as 'ALL' | Decision)}>
                <TabsList>
                  <TabsTrigger value="ALL">Semua</TabsTrigger>
                  <TabsTrigger value="ALLOWED">ALLOWED</TabsTrigger>
                  <TabsTrigger value="BLOCKED">BLOCKED</TabsTrigger>
                </TabsList>
              </Tabs>
              <Button variant="outline" size="sm" onClick={refresh}>
                <RefreshCw className="h-4 w-4" /> Refresh
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => {
                  if (window.confirm('Hapus SEMUA log keamanan?')) {
                    clearLogs()
                    refresh()
                    showToast('Semua log dihapus.')
                  }
                }}
              >
                Hapus Semua Log
              </Button>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Waktu</TableHead>
                    <TableHead>IP Sumber</TableHead>
                    <TableHead>Port Tujuan</TableHead>
                    <TableHead>Jenis Aktivitas</TableHead>
                    <TableHead>Tindakan Sistem</TableHead>
                    <TableHead>Keterangan</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredLogs.map((l) => (
                    <TableRow key={l.id}>
                      <TableCell className="whitespace-nowrap font-mono text-muted-foreground">{l.event_time}</TableCell>
                      <TableCell className="font-mono">{l.source_ip}</TableCell>
                      <TableCell className="font-mono">{l.dest_port}</TableCell>
                      <TableCell>{l.activity_type}</TableCell>
                      <TableCell>
                        <DecisionBadge decision={l.action_taken} />
                      </TableCell>
                      <TableCell className="text-muted-foreground">{l.description || '-'}</TableCell>
                    </TableRow>
                  ))}
                  {filteredLogs.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-muted-foreground">
                        Belum ada log.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}

        {view === 'blacklist' && (
          <Card>
            <CardHeader className="flex flex-row flex-wrap items-center gap-3 space-y-0">
              <div className="flex-1">
                <CardTitle>Blacklist IP</CardTitle>
                <CardDescription>IP di daftar ini selalu diblokir, apa pun port dan aturannya.</CardDescription>
              </div>
              <Dialog open={blOpen} onOpenChange={setBlOpen}>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="h-4 w-4" /> Tambah IP ke Blacklist
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Tambah IP ke Blacklist</DialogTitle>
                    <DialogDescription>IP ini akan selalu diblokir oleh simulasi.</DialogDescription>
                  </DialogHeader>
                  <div className="space-y-3">
                    <div className="space-y-1.5">
                      <Label htmlFor="bIp">IP address</Label>
                      <Input id="bIp" className="font-mono" placeholder="45.148.10.99" value={blForm.ip} onChange={(e) => setBlForm({ ...blForm, ip: e.target.value })} />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="bReason">Alasan</Label>
                      <Input id="bReason" placeholder="Port scanning terdeteksi" value={blForm.reason} onChange={(e) => setBlForm({ ...blForm, reason: e.target.value })} />
                    </div>
                    <Button className="w-full" onClick={submitBlacklist}>
                      Simpan ke Blacklist
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>IP Address</TableHead>
                    <TableHead>Alasan</TableHead>
                    <TableHead>Ditambahkan</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {blacklist.map((b) => (
                    <TableRow key={b.id}>
                      <TableCell className="font-mono font-semibold text-rose-300">{b.ip_address}</TableCell>
                      <TableCell className="text-muted-foreground">{b.reason || '-'}</TableCell>
                      <TableCell className="font-mono text-muted-foreground">{b.added_at}</TableCell>
                      <TableCell>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            if (window.confirm('Hapus IP ini dari blacklist? Setelah ini IP tersebut bisa lolos kalau tidak ada aturan blokir.')) {
                              removeBlacklist(b.id)
                              refresh()
                              showToast('IP dihapus dari blacklist.')
                            }
                          }}
                        >
                          Hapus dari Blacklist
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}

        <footer className="mt-8 text-center text-xs text-muted-foreground">
          CyberShield • React + shadcn/ui (Radix) + Tailwind + Vite • Data simulasi tersimpan di localStorage, bukan traffic jaringan sungguhan
        </footer>
      </main>

      {/* Mobile nav */}
      <nav className="fixed bottom-0 left-0 right-0 flex justify-around border-t bg-card p-2 md:hidden">
        {navItems.map((item) => (
          <Button key={item.id} variant={view === item.id ? 'secondary' : 'ghost'} size="icon" onClick={() => setView(item.id)} title={item.label}>
            {item.icon}
          </Button>
        ))}
      </nav>

      {toast && (
        <div className={`fixed bottom-5 right-5 z-50 max-w-sm rounded-lg border bg-card px-4 py-3 text-sm font-medium shadow-2xl ${toast.ok ? 'border-cyan-400/50' : 'border-rose-500/50'}`}>
          {toast.msg}
        </div>
      )}
    </div>
  )
}
