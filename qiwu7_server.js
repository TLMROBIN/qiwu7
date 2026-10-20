#!/usr/bin/env node
/**
 * 栖梧7班班级管理系统 · 校园网同步服务端（Node 版 · R24 每设备数据槽）
 *
 * 零第三方依赖：只用 Node 自带模块。装了 Node 就能跑（node -v 查看有没有）。
 * 与 Python 版功能完全一致（R24 分槽存储），二选一即可 —— 推荐优先用 Python 版（更好装）。
 *
 * 用法：
 *   node qiwu7_server.js            // 默认 8080
 *   node qiwu7_server.js 9000       // 指定端口
 *   set QIWU7_TOKEN=xxxx && node qiwu7_server.js    // Windows 设口令
 *   QIWU7_TOKEN=xxxx node qiwu7_server.js           // Linux 设口令
 *
 * 数据文件：本脚本同目录 qiwu7_data/data.json（自动创建，自动留 10 份历史备份）
 */
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.argv[2], 10) || parseInt(process.env.QIWU7_PORT || '8080', 10);
const TOKEN = process.env.QIWU7_TOKEN || 'qiwu7';
const BASE_DIR = __dirname;
const DATA_DIR = path.join(BASE_DIR, 'qiwu7_data');
const DATA_FILE = path.join(DATA_DIR, 'data.json');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const MAX_BACKUPS = 10;
const SLOT_IDLE_PRUNE_MS = 180 * 24 * 3600 * 1000;   // 数据槽闲置 180 天才允许清理
const INDEX = path.join(BASE_DIR, 'index.html');   // 主程序（复制一份改名 index.html')

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

const log = m => console.log(`[${new Date().toTimeString().slice(0, 8)}] ${m}`);

function emptyData() { return { rev: 0, ts: 0, slots: {} }; }

function migrate(d) {
  /* 旧版（整包 payload）→ 每设备数据槽；幂等 */
  if (!d || typeof d !== 'object') return emptyData();
  if (d.slots && typeof d.slots === 'object') { d.rev = d.rev || 0; d.ts = d.ts || 0; return d; }
  if (d.payload !== undefined) {
    const ts = d.ts || Date.now();
    return { rev: d.rev || 0, ts, slots: { legacy: { rev: d.rev || 0, ts, payload: d.payload } } };
  }
  return emptyData();
}

function readData() {
  if (!fs.existsSync(DATA_FILE)) return emptyData();
  try {
    return migrate(JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')));
  } catch (e) {
    log('数据文件损坏：' + e.message + ' —— 自动回退到最近一份备份');
    restoreLatest();
    return emptyData();
  }
}
function backupCurrent() {
  if (!fs.existsSync(DATA_FILE)) return;
  try {
    fs.copyFileSync(DATA_FILE, path.join(BACKUP_DIR, `data-${new Date().toISOString().replace(/[:.]/g, '-')}.json`));
    const bks = fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith('data-')).sort();
    while (bks.length > MAX_BACKUPS) fs.unlinkSync(path.join(BACKUP_DIR, bks.shift()));
  } catch (e) { log('备份失败：' + e.message); }
}
function restoreLatest() {
  try {
    const bks = fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith('data-')).sort();
    if (!bks.length) return;
    fs.copyFileSync(path.join(BACKUP_DIR, bks[bks.length - 1]), DATA_FILE);
    log('已恢复备份：' + bks[bks.length - 1]);
  } catch (e) { /* ignore */ }
}
function writeFile(d) {
  /* 原子落盘：先写临时文件再替换 */
  backupCurrent();
  d.ts = Date.now();
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(d), 'utf8');
  fs.renameSync(tmp, DATA_FILE);
}
function pruneSlots(d, keepDev) {
  /* 清理闲置超过 180 天的槽（刚写的除外；只剩一个槽时不清） */
  const now = Date.now();
  const slots = d.slots || {};
  const stale = Object.keys(slots).filter(dev =>
    dev !== keepDev && now - (slots[dev].ts || 0) > SLOT_IDLE_PRUNE_MS);
  if (stale.length && Object.keys(slots).length - stale.length >= 1) {
    stale.forEach(dev => { delete slots[dev]; });
    log(`已清理 ${stale.length} 个闲置数据槽：${stale.join(', ')}`);
  }
}
function writeSlot(payload, dev, baseRev) {
  /* 槽级乐观锁：baseRev 与该槽当前 rev 不一致 → 409；各设备写各的槽互不冲突 */
  const d = readData();
  const slots = d.slots = d.slots || {};
  const cur = slots[dev] || { rev: 0, ts: 0, payload: null };
  if (baseRev != null && cur.rev !== baseRev) {
    return { ok: false, conflict: true, rev: d.rev || 0, slotRev: cur.rev || 0, payload: cur.payload };
  }
  d.rev = (d.rev || 0) + 1;
  slots[dev] = { rev: d.rev, ts: Date.now(), payload };
  pruneSlots(d, dev);
  writeFile(d);
  return { ok: true, rev: d.rev, ts: d.ts, slotRev: slots[dev].rev };
}
function writeLegacy(payload, baseRev) {
  /* 兼容 R23 旧客户端：整包替换 */
  const d = readData();
  if (baseRev != null && (d.rev || 0) !== baseRev) {
    return { ok: false, conflict: true, rev: d.rev || 0, slots: d.slots };
  }
  d.rev = (d.rev || 0) + 1;
  d.slots = { legacy: { rev: d.rev, ts: Date.now(), payload } };
  writeFile(d);
  return { ok: true, rev: d.rev, ts: d.ts };
}

function sendJSON(res, obj, code) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(code || 200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  });
  res.end(body);
}
function serveIndex(req, res) {
  const file = fs.existsSync(INDEX) ? INDEX : findHtml();
  if (!file) { res.writeHead(404); return res.end('index.html 不存在'); }
  const body = fs.readFileSync(file);
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store' });
  res.end(body);
}
function findHtml() {
  const f = fs.readdirSync(BASE_DIR).filter(x => /\.html$/i.test(x) && !/^校园网部署说明/.test(x));
  return f.length ? path.join(BASE_DIR, f[0]) : null;
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://localhost');
  const q = u.searchParams;
  const check = () => q.get('token') === TOKEN;

  if (req.method === 'OPTIONS') return sendJSON(res, { ok: true });

  if (u.pathname === '/api/ping') {
    return sendJSON(res, { ok: true, name: 'qiwu7', rev: readData().rev, time: new Date().toLocaleString('zh-CN') });
  }

  if (u.pathname === '/api/sync' && req.method === 'GET') {
    if (!check()) return sendJSON(res, { ok: false, error: '口令不对' }, 401);
    const d = readData();
    const slots = d.slots || {};
    /* 客户端带 revs（各槽已知版本，JSON）→ 只回有变化的槽，省带宽 */
    let revs = {};
    try { revs = JSON.parse(q.get('revs') || '{}'); if (!revs || typeof revs !== 'object') revs = {}; } catch (e) { revs = {}; }
    const changed = {};
    Object.keys(slots).forEach(dev => {
      if (!(dev in revs && revs[dev] === slots[dev].rev)) changed[dev] = slots[dev];
    });
    const slotsRev = {};
    Object.keys(slots).forEach(dev => { slotsRev[dev] = slots[dev].rev || 0; });
    return sendJSON(res, { ok: true, rev: d.rev || 0, ts: d.ts || 0, slots: changed, count: Object.keys(slots).length, slotsRev });
  }

  if (u.pathname === '/api/backup') {
    if (!check()) return sendJSON(res, { ok: false, error: '口令不对' }, 401);
    const body = Buffer.from(JSON.stringify(readData()), 'utf8');
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': body.length,
      /* HTTP 头只能装 ASCII：中文文件名必须百分号编码（RFC 5987） */
      'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent('栖梧7班数据备份.json')}`,
    });
    return res.end(body);
  }

  if (u.pathname === '/api/sync' && req.method === 'POST') {
    if (!check()) return sendJSON(res, { ok: false, error: '口令不对' }, 401);
    let raw = '';
    let tooBig = false;
    req.on('data', c => { raw += c; if (raw.length > 50 * 1024 * 1024) { tooBig = true; req.destroy(); } });
    req.on('end', () => {
      if (tooBig) return;
      let reqObj = {};
      try { reqObj = raw ? JSON.parse(raw) : {}; } catch (e) {
        return sendJSON(res, { ok: false, error: '请求不是合法 JSON：' + e.message }, 400);
      }
      const payload = reqObj.payload;
      if (payload === undefined || payload === null) {
        return sendJSON(res, { ok: false, error: '缺少 payload' }, 400);
      }
      const baseRev = reqObj.baseRev;
      let r;
      let dev = null;
      if (reqObj.deviceId !== undefined && reqObj.deviceId !== null) {
        /* R24 新协议：写自己的数据槽 */
        dev = String(reqObj.deviceId).slice(0, 64) || 'unknown';
        r = writeSlot(payload, dev, baseRev);
      } else {
        /* 旧协议：整包替换（兼容升级过渡期） */
        r = writeLegacy(payload, baseRev);
      }
      if (!r.ok) {
        return sendJSON(res, {
          ok: false, conflict: true, rev: r.rev || 0, slotRev: r.slotRev != null ? r.slotRev : undefined,
          payload: r.payload, slots: r.slots,
          error: '数据已被其他设备更新，请合并后重试',
        }, 409);
      }
      log(`已同步 rev=${r.rev}（${dev || 'legacy'}，来自 ${req.socket.remoteAddress}）`);
      return sendJSON(res, { ok: true, rev: r.rev, ts: r.ts, slotRev: r.slotRev });
    });
    return;
  }

  if (req.method === 'GET') return serveIndex(req, res);
  sendJSON(res, { ok: false, error: 'not found' }, 404);
});

server.on('error', e => {
  console.error(`端口 ${PORT} 起不来：${e.message}\n换一个端口试试，例如：node qiwu7_server.js 9000`);
  process.exit(1);
});

server.listen(PORT, () => {
  console.log('='.repeat(62));
  console.log('  栖梧7班班级管理系统 · 校园网服务端已启动（R24 数据槽版 · Node）');
  console.log('='.repeat(62));
  console.log(`  本机访问：   http://127.0.0.1:${PORT}`);
  console.log('  局域网访问： http://<本机IP>:' + PORT + '   ← 把这个地址发给老师 / 输进一体机');
  console.log(`  班级口令：   ${TOKEN}`);
  if (TOKEN === 'qiwu7') {
    console.log('  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
    console.log('  !! 安全警告：你现在用的是【默认口令 qiwu7】，请尽快改掉  !!');
    console.log('  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
  }
  console.log(`  数据文件：   ${DATA_FILE}`);
  console.log('  提醒：第一次打开网页后，要去「设置 / 数据 → 🌐 校园网同步」');
  console.log('        填上面的地址与口令，点「立即同步」，三端就通了。');
  console.log('='.repeat(62));
});
