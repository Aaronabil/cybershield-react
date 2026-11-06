# CyberShield — React + shadcn/ui (Vercel)

Aplikasi web untuk memantau aktivitas jaringan, mengelola aturan firewall,
dan menampilkan simulasi ancaman keamanan jaringan.

**Identitas:** Muhamad Nabil Faiz Amrullah — NIM 242502040042 — Kelas 3TI01

**Stack:** React 19 + Vite + TypeScript + Tailwind CSS + **shadcn/ui beneran**
(komponen di `src/components/ui`, dibangun di atas Radix UI: Button, Card,
Badge, Input, Label, Switch, Dialog, Table, Tabs, Separator) + Recharts
untuk grafik + lucide-react untuk ikon.

Ini adalah versi **shadcn React beneran** dari CyberShield. Versi pengumpulan
tugas (HTML + PHP + MySQL) tetap ada di repo `cybershield` (PHP) dan
`Aaronabil/cybershield` di GitHub Pages (versi statis).

## Fitur

- **Dashboard Monitoring:** total paket diperiksa, koneksi diizinkan,
  ancaman diblokir, aturan firewall aktif, grafik traffic live (Recharts),
  donat Allowed vs Blocked, log terbaru.
- **Manajemen Aturan Firewall:** tambah aturan (Dialog shadcn), IP
  (`*` / IP / CIDR) + port, aksi ALLOW/BLOCK, Switch aktif/nonaktif, hapus.
- **Simulasi Traffic & Serangan:** traffic otomatis tiap 1,5 detik, 4
  simulasi serangan (DDoS, Port Scan, SQL Injection, Brute Force), live feed,
  status ALLOWED / BLOCKED.
- **Log Keamanan:** waktu, IP sumber, port tujuan, jenis aktivitas,
  tindakan sistem, pencarian + filter (Tabs).
- **Blacklist IP:** tambah (Dialog) dan hapus IP.

## Data

Tidak ada server di versi ini: data (aturan, log, blacklist) disimpan di
`localStorage` browser dengan skema dan data awal yang sama persis dengan
`database.sql` versi PHP. Logika penilaiannya juga sama: blacklist dulu,
lalu aturan BLOCK didahulukan, lalu port spesifik sebelum port 0.

## Menjalankan lokal

```bash
npm install
npm run dev     # http://localhost:5173
npm run build   # build produksi ke dist/
```

## Deploy (Vercel)

Project Vercel terhubung ke repo GitHub ini; setiap push ke `main`
otomatis deploy. Build command: `npm run build`, output: `dist`.
