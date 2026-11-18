<?php
declare(strict_types=1);
session_start();
$_SESSION['t'] = $_SESSION['t'] ?? bin2hex(random_bytes(16));

const MAKS = 25 * 1048576;
const IZIN = ['pdf','doc','docx','xls','xlsx','ppt','pptx','txt','csv','png','jpg','jpeg'];
$DIR = __DIR__ . '/data'; $UP = "$DIR/uploads"; $DB = "$DIR/data.json";
is_dir($UP) || mkdir($UP, 0750, true);
is_file("$DIR/.htaccess") || file_put_contents("$DIR/.htaccess", "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");

$IND = array_map(fn($l) => explode('|', $l), explode("\n", trim(<<<'T'
10101|Penerapan Standar Data Statistik (SDS)|100
10201|Penerapan Metadata Statistik|100
10301|Penerapan Interoperabilitas Data|100
10401|Penerapan Kode Referensi|100
20101|Relevansi Data Terhadap Pengguna|60
20102|Proses Identifikasi Kebutuhan Data|40
20201|Penilaian Akurasi Data|100
20301|Penjaminan Aktualitas Data|50
20302|Pemantauan Ketepatan Waktu Diseminasi|50
20401|Ketersediaan Data untuk Pengguna Data|34
20402|Akses Media Penyebarluasan Data|33
20403|Penyediaan Format Data|33
20501|Keterbandingan Data|50
20502|Konsistensi Statistik|50
30101|Pendefinisian Kebutuhan Statistik|33
30102|Desain Statistik|33
30103|Penyiapan Instrumen|34
30201|Proses Pengumpulan Data / Akuisisi Data|100
30301|Pengolahan Data|50
30302|Analisis Data|50
30401|Diseminasi Data|100
40101|Penjaminan Transparansi Informasi Statistik|25
40102|Penjaminan Netralitas dan Obyektivitas terhadap Penggunaan Sumber Data Metodologi|25
40103|Penjaminan Kualitas Data|25
40104|Penjaminan Konfidensialitas Data|25
40201|Penerapan Kompetensi SDM Bidang Statistik|50
40202|Penerapan Kompetensi SDM Bidang Manajemen Data|50
40301|Kolaborasi Penyelenggaraan Kegiatan Statistik|25
40302|Penyelenggaraan Forum Satu Data|25
40303|Kolaborasi dengan Pembina Data Statistik|25
40304|Pelaksanaan Tugas Sebagai Wali Data|25
50101|Penggunaan Data Statistik Dasar untuk Perencanaan, Monitoring, dan Evaluasi, dan/atau Penyusunan Kebijakan|34
50102|Penggunaan Data Statistik Sektoral untuk Perencanaan, Monitoring, dan Evaluasi, dan/atau Penyusunan Kebijakan|33
50103|Sosialisasi dan Literasi Data Statistik|33
50201|Pelaksanaan Rekomendasi Kegiatan Statistik|100
50301|Perencanaan Pembangunan Statistik|33
50302|Penyebarluasan Data|33
50303|Pemanfaatan Big Data|34
T)));
$KODE = array_column($IND, 0);

/* Baca/ubah data.json dengan kunci berkas */
function db(?callable $fn = null): array {
    global $DB;
    $f = fopen($DB, 'c+'); flock($f, LOCK_EX);
    $d = json_decode((string)stream_get_contents($f), true) ?: [];
    if ($fn) { $fn($d); ftruncate($f, 0); rewind($f); fwrite($f, json_encode($d, JSON_UNESCAPED_UNICODE)); }
    flock($f, LOCK_UN); fclose($f);
    return $d;
}
function keluar($d, int $c = 200) {
    http_response_code($c); header('Content-Type: application/json');
    echo json_encode($d, JSON_UNESCAPED_UNICODE); exit;
}

/* ---- API ---- */
$aksi = $_GET['aksi'] ?? '';
if ($aksi === 'unduh') {
    $kode = $_GET['kode'] ?? ''; $rows = db()[$kode]['files'] ?? [];
    foreach ($rows as $r) if ($r['id'] === ($_GET['id'] ?? '')) {
        $p = "$UP/{$r['id']}.{$r['ext']}";
        if (!is_file($p)) break;
        header('Content-Type: application/octet-stream'); header('X-Content-Type-Options: nosniff');
        header("Content-Disposition: attachment; filename*=UTF-8''" . rawurlencode($r['nama']));
        header('Content-Length: ' . filesize($p)); readfile($p); exit;
    }
    http_response_code(404); exit('Berkas tidak ditemukan');
}
if ($aksi) {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !hash_equals($_SESSION['t'], $_SERVER['HTTP_X_CSRF'] ?? ''))
        keluar(['galat' => 'Sesi tidak valid. Muat ulang halaman.'], 403);
    $kode = $_POST['kode'] ?? '';
    if (!in_array($kode, $KODE, true)) keluar(['galat' => 'Berkas terlalu besar atau tidak terkirim'], 400);

    if ($aksi === 'unggah') {
        $f = $_FILES['berkas'] ?? null;
        if (!$f) keluar(['galat' => 'Berkas terlalu besar atau tidak terkirim'], 400);
        if ($f['error'] !== UPLOAD_ERR_OK) keluar(['galat' => $f['error'] === UPLOAD_ERR_INI_SIZE ? 'Melebihi batas server' : 'Gagal mengunggah'], 400);
        $nama = preg_replace('/[\x00-\x1F\/\\\\]/', '', basename($f['name']));
        $ext = strtolower(pathinfo($nama, PATHINFO_EXTENSION));
        if (!in_array($ext, IZIN, true)) keluar(['galat' => 'Tipe tidak didukung'], 415);
        if ($f['size'] > MAKS) keluar(['galat' => 'Lebih dari 25 MB'], 413);
        if ($f['size'] === 0) keluar(['galat' => 'Berkas kosong'], 400);
        $id = bin2hex(random_bytes(8));
        if (!move_uploaded_file($f['tmp_name'], "$UP/$id.$ext")) keluar(['galat' => 'Gagal menyimpan berkas'], 500);
        $rec = ['id' => $id, 'nama' => mb_substr($nama, 0, 150), 'ukuran' => $f['size'], 'ext' => $ext];
        db(function (&$d) use ($kode, $rec) { $d[$kode]['files'][] = $rec; });
        keluar($rec);
    }
    if ($aksi === 'hapus') {
        db(function (&$d) use ($kode, $UP) {
            foreach ($d[$kode]['files'] ?? [] as $k => $r) if ($r['id'] === ($_POST['id'] ?? '')) {
                @unlink("$UP/{$r['id']}.{$r['ext']}"); unset($d[$kode]['files'][$k]);
            }
            $d[$kode]['files'] = array_values($d[$kode]['files'] ?? []);
        });
        keluar(['ok' => 1]);
    }
    if ($aksi === 'simpan') {
        db(function (&$d) use ($kode) {
            $d[$kode]['level'] = max(0, min(5, (int)($_POST['level'] ?? 0)));
            $d[$kode]['catatan'] = mb_substr($_POST['catatan'] ?? '', 0, 2000);
        });
        keluar(['ok' => 1]);
    }
    keluar(['galat' => 'Aksi tidak dikenal'], 400);
}
$state = db();
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Unggah Bukti Dukung EPSS 2024</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@500;700&family=Instrument+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#F2F4F1;--surface:#FFFFFF;--ink:#16252B;--muted:#5B6B70;--line:#D9DFDC;--accent:#0E7C86;--soft:#D5EEF0;--ok:#2E7D4F;--err:#B3261E;--track:#E3E8E5;box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px);color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#11191C;--surface:#192327;--ink:#E6EEEF;--muted:#93A5A9;--line:#2A383C;--accent:#4FC3CE;--soft:#1D3A3F;--ok:#5CC48A;--err:#F0847B;--track:#25333A;color-scheme:dark}}
:root[data-theme="dark"]{--bg:#11191C;--surface:#192327;--ink:#E6EEEF;--muted:#93A5A9;--line:#2A383C;--accent:#4FC3CE;--soft:#1D3A3F;--ok:#5CC48A;--err:#F0847B;--track:#25333A;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:400 16px/1.5 "Instrument Sans",system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:28px 18px 64px}
h1,h2,.big{font-family:"Bricolage Grotesque","Instrument Sans",system-ui,sans-serif;margin:0}
h1{font-size:1.5rem}h2{font-size:1.15rem;margin:28px 0 10px}
header{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:20px}
header p{margin:2px 0 0;color:var(--muted);font-size:.92rem}
button,input,textarea{font:inherit;color:inherit}button{cursor:pointer}
.btn{border:1px solid var(--line);background:var(--surface);border-radius:8px;padding:7px 12px;font-size:.9rem;font-weight:500}
.btn:hover{border-color:var(--accent)}.btn.sm{padding:4px 9px;font-size:.8rem}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--bg)}
:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.hero{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:22px}
.hero-top{display:flex;gap:24px;flex-wrap:wrap;align-items:flex-end;justify-content:space-between}
.big{font-size:4.25rem;line-height:1;font-weight:700;letter-spacing:-.03em;font-variant-numeric:tabular-nums}
.big small{font-size:1.4rem;color:var(--muted);font-weight:500}
.lbl{color:var(--muted);font-size:.9rem}
.doms{display:grid;gap:9px;margin-top:20px}
.dom{display:grid;grid-template-columns:minmax(0,1fr) 2fr 44px;gap:12px;align-items:center;font-size:.9rem}
.dom span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar{height:8px;background:var(--track);border-radius:99px;overflow:hidden}
.bar i{display:block;height:100%;width:0;background:var(--accent);border-radius:99px;transition:width .2s linear}
.dom b{text-align:right;font-variant-numeric:tabular-nums}
.stats{display:grid;grid-template-columns:repeat(3,1fr);margin-top:18px;border-top:1px solid var(--line)}
.stat{padding-top:12px}.stat+.stat{padding-left:16px;border-left:1px solid var(--line)}
.stat b{display:block;font:700 1.4rem/1.2 "Bricolage Grotesque",sans-serif}
.stat span{color:var(--muted);font-size:.85rem}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-top:22px}
.tabs .btn[aria-pressed="true"],.lv .btn[aria-pressed="true"]{background:var(--accent);border-color:var(--accent);color:var(--bg)}
.ind{background:var(--surface);border:1px solid var(--line);border-radius:12px;margin-bottom:8px}
.ind summary{display:flex;gap:12px;align-items:center;padding:13px 14px;cursor:pointer;list-style:none}
.ind summary::-webkit-details-marker{display:none}
.ind summary::before{content:"+";width:18px;color:var(--muted);font-weight:600}
.ind[open] summary::before{content:"–"}
.code{font-weight:600;color:var(--accent);font-variant-numeric:tabular-nums}
.nm{flex:1;min-width:0;font-weight:500}
.chip{font-size:.78rem;padding:2px 9px;border-radius:99px;background:var(--track);color:var(--muted);white-space:nowrap}
.chip.on{background:var(--soft);color:var(--accent);font-weight:600}
.body{padding:2px 14px 16px 44px;display:grid;gap:14px}
.lv{display:flex;gap:6px;flex-wrap:wrap}.lv .btn{min-width:42px}
.desc{margin:6px 0 0;color:var(--muted);font-size:.9rem}
.sec{font-weight:600;font-size:.9rem;margin-bottom:6px;display:block}
ul{list-style:none;margin:0;padding:0}
.file{display:grid;grid-template-columns:1fr auto;gap:2px 12px;align-items:center;padding:8px 0;border-top:1px solid var(--line)}
.fm{display:flex;justify-content:space-between;gap:10px;font-size:.9rem;min-width:0}
.fn{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:inherit}.fs{color:var(--muted);white-space:nowrap}
.file .bar{grid-column:1;height:6px}.fb{grid-row:1/3;grid-column:2;display:flex;gap:6px}
.file.done .bar i{background:var(--ok)}.file.error .bar i{background:var(--err)}.file.error .fs{color:var(--err)}
input[type=url],textarea{width:100%;border:1px solid var(--line);background:var(--bg);border-radius:8px;padding:8px 10px}
textarea{min-height:64px;resize:vertical}
.hint{color:var(--muted);font-size:.82rem;margin:6px 0 0}
@media (max-width:600px){.big{font-size:3.2rem}.body{padding-left:14px}.dom{grid-template-columns:1fr 1fr 40px}.chip.ev{display:none}}
@media (prefers-reduced-motion:reduce){.bar i{transition:none}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div><h1>Unggah Bukti Dukung EPSS 2024</h1><p>Jawab setiap indikator, lampirkan bukti dukung, dan pantau indeks secara langsung. Berdasarkan LKE Offline EPSS 2024.</p></div>
    <button class="btn" id="theme" type="button">Ganti tema</button>
  </header>
  <section class="hero" aria-label="Ringkasan">
    <div class="hero-top">
      <div><div class="lbl">Indeks Pembangunan Statistik</div><div class="big"><span id="idx">0.00</span><small> / 5</small></div></div>
      <div class="lbl" id="upwrap" hidden style="min-width:200px"><span id="uptxt"></span><div class="bar" style="margin-top:6px"><i id="upfill"></i></div></div>
    </div>
    <div class="doms" id="doms"></div>
    <div class="stats">
      <div class="stat"><b id="sAns">0</b><span>Indikator terjawab</span></div>
      <div class="stat"><b id="sEv">0</b><span>Berkas bukti terunggah</span></div>
      <div class="stat"><b id="sUp">0</b><span>Sedang diunggah</span></div>
    </div>
  </section>
  <div class="tabs" id="tabs" role="group" aria-label="Filter domain"></div>
  <div id="inds"></div>
  <div id="live" aria-live="polite" style="position:absolute;width:1px;height:1px;overflow:hidden"></div>
</div>

<script>
const TOKEN = <?= json_encode($_SESSION['t']) ?>;
const SERVER = <?= json_encode($state ?: new stdClass, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP) ?>;
const MAX = 25 * 1048576, CONC = 3;
const DOMAINS = [["Prinsip SDI",28],["Kualitas Data",24],["Proses Bisnis Statistik",19],["Kelembagaan",17],["Statistik Nasional",12]];
const IND = <?= json_encode(array_map(fn($r) => ['c' => $r[0], 'n' => $r[1], 'w' => (int)$r[2]], $IND), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG) ?>.map(i => ({...i, d: +i.c[0] - 1, a: i.c.slice(0, 3)}));
const LV = ["Belum dilakukan oleh seluruh Produsen Data","Telah dilakukan oleh setiap Produsen Data sesuai standarnya masing-masing","Telah dilakukan berdasarkan prosedur baku yang berlaku untuk seluruh Produsen Data","Telah dilakukan reviu dan evaluasi secara berkala","Telah dilakukan pemutakhiran dalam rangka peningkatan kualitas"];

const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const fmt = b => b < 1024 ? b + " B" : b < 1048576 ? (b/1024).toFixed(0) + " KB" : (b/1048576).toFixed(1) + " MB";
const fm = o => { const f = new FormData(); for (const k in o) f.append(k, o[k]); return f; };
const post = (a, o) => fetch("?aksi=" + a, {method: "POST", headers: {"X-CSRF": TOKEN}, body: fm(o)});

const S = {};
IND.forEach(i => { const r = SERVER[i.c] || {};
  S[i.c] = {level: r.level || 0, note: r.catatan || "",
    files: (r.files || []).map(x => ({id: x.id, name: x.nama, size: x.ukuran, loaded: x.ukuran, speed: 0, status: "done", c: i.c}))}; });
const T = {};
function save(c) { clearTimeout(T[c]); T[c] = setTimeout(() => { const s = S[c]; post("simpan", {kode: c, level: s.level, catatan: s.note}); }, 400); }

/* Skor: level x bobot dalam aspek; domain = rata-rata aspek (bobot aspek dianggap sama); indeks = domain x bobot domain */
function scores() {
  const asp = {};
  IND.forEach(i => { const a = asp[i.a] || (asp[i.a] = {d: i.d, s: 0}); a.s += S[i.c].level * i.w / 100; });
  const dom = DOMAINS.map((_, d) => { const as = Object.values(asp).filter(a => a.d === d); return as.reduce((s, a) => s + a.s, 0) / as.length; });
  return {dom, idx: dom.reduce((s, v, d) => s + v * DOMAINS[d][1] / 100, 0)};
}
function dash() {
  const {dom, idx} = scores();
  $("idx").textContent = idx.toFixed(2);
  dom.forEach((v, k) => { $("db" + k).style.width = v / 5 * 100 + "%"; $("dv" + k).textContent = v.toFixed(2); });
  const all = IND.flatMap(i => S[i.c].files);
  const act = all.filter(f => f.status === "uploading" || f.status === "queued");
  const tot = act.reduce((s, f) => s + f.size, 0), ld = act.reduce((s, f) => s + f.loaded, 0);
  $("sAns").textContent = IND.filter(i => S[i.c].level).length + " / " + IND.length;
  $("sEv").textContent = all.filter(f => f.status === "done").length;
  $("sUp").textContent = act.length;
  $("upwrap").hidden = !act.length;
  $("upfill").style.width = (tot ? ld / tot * 100 : 0) + "%";
  $("uptxt").textContent = "Mengunggah " + act.length + " berkas · " + Math.floor(tot ? ld / tot * 100 : 0) + "%";
}

$("doms").innerHTML = DOMAINS.map((d, k) => `<div class="dom"><span>${k+1}. ${d[0]} (${d[1]}%)</span><div class="bar"><i id="db${k}"></i></div><b id="dv${k}">0.00</b></div>`).join("");
$("tabs").innerHTML = ['<button class="btn" type="button" data-tab="all" aria-pressed="true">Semua domain</button>'].concat(DOMAINS.map((d, k) => `<button class="btn" type="button" data-tab="${k}" aria-pressed="false">${k+1}. ${d[0]}</button>`)).join("");
$("inds").innerHTML = DOMAINS.map((d, k) => `<section data-d="${k}"><h2>${k+1}. ${d[0]}</h2>` + IND.filter(i => i.d === k).map(i => `
<details class="ind" id="i${i.c}"><summary><span class="code">${i.c}</span><span class="nm">${esc(i.n)}</span><span class="chip ev" id="ev${i.c}"></span><span class="chip" id="ch${i.c}"></span></summary>
<div class="body">
 <div><span class="sec">Tingkat kematangan (bobot ${i.w}%)</span>
  <div class="lv" role="group" aria-label="Tingkat kematangan ${i.c}">${[1,2,3,4,5].map(n => `<button class="btn" type="button" data-c="${i.c}" data-lv="${n}" aria-pressed="false">${n}</button>`).join("")}</div>
  <p class="desc" id="ds${i.c}"></p></div>
 <div><span class="sec">Berkas bukti dukung</span>
  <button class="btn primary sm" type="button" data-pick="${i.c}">Unggah berkas</button><input type="file" multiple hidden id="in${i.c}" data-up="${i.c}" accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv,.png,.jpg,.jpeg">
  <p class="hint">PDF, Office, teks, CSV, atau gambar. Maksimal 25 MB per berkas. Setiap berkas yang terunggah otomatis mendapat tautan yang bisa disalin.</p><ul id="fl${i.c}"></ul></div>
 <div><label class="sec" for="nt${i.c}">Catatan</label><textarea id="nt${i.c}" data-f="note" data-c="${i.c}"></textarea></div>
</div></details>`).join("") + "</section>").join("");

function paint(c) {
  const s = S[c], n = s.files.filter(f => f.status === "done").length;
  $("ch" + c).textContent = s.level ? "Tingkat " + s.level : "Belum dijawab";
  $("ch" + c).className = "chip" + (s.level ? " on" : "");
  $("ev" + c).textContent = n ? n + " berkas" : "";
  $("ev" + c).style.display = n ? "" : "none";
  $("ds" + c).textContent = s.level ? LV[s.level - 1] : "Pilih tingkat yang sesuai kondisi saat ini.";
  document.querySelectorAll(`#i${c} [data-lv]`).forEach(b => b.setAttribute("aria-pressed", +b.dataset.lv === s.level));
  $("nt" + c).value = s.note;
}
function paintFiles(c) {
  $("fl" + c).innerHTML = S[c].files.map(f => `<li class="file ${f.status}" id="f${f.id}"><div class="fm">${f.status === "done" ? `<a class="fn" href="?aksi=unduh&kode=${c}&id=${f.id}">${esc(f.name)}</a>` : `<span class="fn">${esc(f.name)}</span>`}<span class="fs"></span></div><div class="bar" role="progressbar" aria-label="${esc(f.name)}" aria-valuemin="0" aria-valuemax="100"><i></i></div><div class="fb">${f.status === "done" ? `<button class="btn sm" type="button" data-copy="${f.id}" data-c="${c}">Salin tautan</button>` : ""}<button class="btn sm" type="button" data-fa="${f.id}" data-c="${c}">${f.status === "done" || f.status === "error" ? "Hapus" : "Batal"}</button></div></li>`).join("");
  S[c].files.forEach(tick); paint(c);
}
function tick(f) {
  const el = $("f" + f.id); if (!el) return;
  const p = Math.floor(f.loaded / f.size * 100);
  el.querySelector(".bar i").style.width = p + "%";
  el.querySelector(".bar").setAttribute("aria-valuenow", p);
  el.querySelector(".fs").textContent = f.status === "uploading" ? p + "% · " + fmt(f.speed) + "/dtk" : f.status === "queued" ? "Menunggu" : f.status === "error" ? f.err : fmt(f.size) + " · Terunggah";
}
IND.forEach(i => { paint(i.c); paintFiles(i.c); });

/* ---- Unggah ke PHP (upload.php sudah menyatu di ?aksi=unggah) ---- */
function addFiles(c, list) {
  [...list].forEach(file => {
    const ext = file.name.split(".").pop().toLowerCase();
    const f = {id: "t" + Math.random().toString(36).slice(2, 10), name: file.name, size: file.size || 1, loaded: 0, speed: 0, status: "queued", file, c};
    if (!["pdf","doc","docx","xls","xlsx","ppt","pptx","txt","csv","png","jpg","jpeg"].includes(ext)) { f.status = "error"; f.err = "Tidak didukung"; }
    else if (file.size > MAX) { f.status = "error"; f.err = "Lebih dari 25 MB"; }
    else if (!file.size) { f.status = "error"; f.err = "Berkas kosong"; }
    S[c].files.push(f);
  });
  paintFiles(c); pump(); dash();
}
function pump() {
  const all = IND.flatMap(i => S[i.c].files);
  let run = all.filter(f => f.status === "uploading").length;
  for (const f of all) { if (run >= CONC) break; if (f.status === "queued") { begin(f); run++; } }
}
function begin(f) {
  f.status = "uploading"; f.t0 = performance.now();
  const x = new XMLHttpRequest(); f.xhr = x;
  x.open("POST", "?aksi=unggah"); x.setRequestHeader("X-CSRF", TOKEN);
  x.upload.onprogress = e => { if (e.lengthComputable) { f.loaded = e.loaded / e.total * f.size; f.speed = f.loaded / ((performance.now() - f.t0) / 1000 || 1); tick(f); dash(); } };
  x.onload = () => { let r = {}; try { r = JSON.parse(x.responseText); } catch (e) {}
    if (x.status === 200 && r.id) { f.id = r.id; end(f, true); } else end(f, false, r.galat || "Gagal mengunggah (" + x.status + ")"); };
  x.onerror = () => end(f, false, "Gangguan jaringan");
  x.send(fm({berkas: f.file, kode: f.c}));
  paintFiles(f.c);
}
function end(f, ok, msg) {
  f.speed = 0;
  if (ok) { f.status = "done"; f.loaded = f.size; $("live").textContent = f.name + " berhasil diunggah"; } else { f.status = "error"; f.err = msg; }
  paintFiles(f.c); pump(); dash();
}

$("inds").addEventListener("click", e => {
  const b = e.target.closest("button"); if (!b) return;
  if (b.dataset.lv) { S[b.dataset.c].level = +b.dataset.lv; paint(b.dataset.c); dash(); save(b.dataset.c); }
  else if (b.dataset.pick) $("in" + b.dataset.pick).click();
  else if (b.dataset.copy) {
    const u = new URL("?aksi=unduh&kode=" + b.dataset.c + "&id=" + b.dataset.copy, location.href).href;
    const ok = () => { b.textContent = "Tersalin"; setTimeout(() => { b.textContent = "Salin tautan"; }, 1500); };
    if (navigator.clipboard) navigator.clipboard.writeText(u).then(ok, () => prompt("Salin tautan:", u)); else prompt("Salin tautan:", u);
  }
  else if (b.dataset.fa) {
    const c = b.dataset.c, f = S[c].files.find(x => x.id === b.dataset.fa);
    if (f.status === "uploading" && f.xhr) f.xhr.abort();
    if (f.status === "done") post("hapus", {kode: c, id: f.id});
    S[c].files.splice(S[c].files.indexOf(f), 1); paintFiles(c); pump(); dash();
  }
});
$("inds").addEventListener("change", e => { if (e.target.dataset.up) { addFiles(e.target.dataset.up, e.target.files); e.target.value = ""; } });
$("inds").addEventListener("input", e => { const t = e.target; if (t.dataset.f) { S[t.dataset.c][t.dataset.f] = t.value; save(t.dataset.c); } });
$("tabs").addEventListener("click", e => {
  const b = e.target.closest("button"); if (!b) return;
  document.querySelectorAll("#tabs button").forEach(x => x.setAttribute("aria-pressed", x === b));
  document.querySelectorAll("#inds section").forEach(s => s.hidden = b.dataset.tab !== "all" && s.dataset.d !== b.dataset.tab);
});
$("theme").onclick = () => { const r = document.documentElement; const dark = r.dataset.theme ? r.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches; r.dataset.theme = dark ? "light" : "dark"; };
dash();
</script>
</body>
</html>
