#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
栖梧7班班级管理系统 · 校园网同步服务端（Python 版 · R24 每设备数据槽）

零第三方依赖：只用 Python 标准库。Windows / Linux / macOS 通用。
Python 3.6+ 即可（Windows 上装 Python 时记得勾选 "Add Python to PATH"）。

做什么：
  1) 托管主程序网页（浏览器打开 http://服务器IP:端口 就能用）
  2) 提供 /api/sync 接口，把每个设备的数据存成独立「数据槽」
     —— 教师端 / 班级端 / 个人端各写各的槽，读的时候把所有槽合并，
       任何一台设备都不可能覆盖别人刚写的数据（R24 之前是整包替换，
       学生端一同步就可能把教师端推的名单/成绩冲掉，现已根治）

数据文件：本脚本同目录 qiwu7_data/data.json（自动创建，自动留 10 份历史备份）
"""
import json, os, sys, time, shutil, threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote

# ============ 配置 ============
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get('QIWU7_PORT', '8080'))
TOKEN = os.environ.get('QIWU7_TOKEN', 'qiwu7')      # 班级口令，务必改成自己的
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'qiwu7_data')
DATA_FILE = os.path.join(DATA_DIR, 'data.json')
BACKUP_DIR = os.path.join(DATA_DIR, 'backups')
MAX_BACKUPS = 10
SLOT_IDLE_PRUNE_MS = 180 * 24 * 3600 * 1000   # 数据槽闲置超过 180 天才允许清理（避免暑假误删）
LOCK = threading.Lock()

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)


def log(msg):
    print('[%s] %s' % (time.strftime('%H:%M:%S'), msg), flush=True)


def empty_slots():
    return {'rev': 0, 'ts': 0, 'slots': {}}


def migrate(d):
    """旧版（整包 payload）数据文件 → 每设备数据槽结构；迁移是幂等的"""
    if not isinstance(d, dict):
        return empty_slots()
    if isinstance(d.get('slots'), dict):
        d.setdefault('rev', 0)
        d.setdefault('ts', 0)
        return d
    if d.get('payload') is not None:
        # R23 及更早的整包存档：包成名为 legacy 的槽，新客户端合并时会自然吸收
        ts = d.get('ts') or int(time.time() * 1000)
        return {'rev': d.get('rev', 0), 'ts': ts,
                'slots': {'legacy': {'rev': d.get('rev', 0), 'ts': ts, 'payload': d['payload']}}}
    return empty_slots()


def read_data():
    """读取服务器上的数据；没有就返回空包（rev=0）。旧格式自动迁移。"""
    if not os.path.exists(DATA_FILE):
        return empty_slots()
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            d = json.load(f)
        return migrate(d)
    except Exception as e:
        log('数据文件损坏：%s —— 自动回退到最近一份备份' % e)
        restore_latest_backup()
        return empty_slots()


def backup_current():
    """写入前把现有文件复制一份到 backups/，只保留最近 MAX_BACKUPS 份"""
    if not os.path.exists(DATA_FILE):
        return
    name = 'data-%s.json' % time.strftime('%Y%m%d-%H%M%S')
    try:
        shutil.copy2(DATA_FILE, os.path.join(BACKUP_DIR, name))
    except Exception as e:
        log('备份失败：%s' % e)
        return
    try:
        bks = sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith('data-')])
        while len(bks) > MAX_BACKUPS:
            os.remove(os.path.join(BACKUP_DIR, bks.pop(0)))
    except Exception:
        pass


def restore_latest_backup():
    try:
        bks = sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith('data-')])
        if not bks:
            return False
        shutil.copy2(os.path.join(BACKUP_DIR, bks[-1]), DATA_FILE)
        log('已恢复备份：%s' % bks[-1])
        return True
    except Exception:
        return False


def write_file(d):
    """原子落盘：先写临时文件再替换，断电也不会写坏"""
    backup_current()
    d['ts'] = int(time.time() * 1000)
    tmp = DATA_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(d, f, ensure_ascii=False)
    os.replace(tmp, DATA_FILE)


def prune_slots(d, keep_dev=None):
    """清理闲置超过 180 天的数据槽（刚写入的槽除外；只剩一个槽时不清）"""
    now = int(time.time() * 1000)
    slots = d.get('slots') or {}
    stale = [dev for dev, s in slots.items()
             if dev != keep_dev and now - (s.get('ts') or 0) > SLOT_IDLE_PRUNE_MS]
    if stale and len(slots) - len(stale) >= 1:
        for dev in stale:
            del slots[dev]
        log('已清理 %d 个闲置数据槽：%s' % (len(stale), ', '.join(stale)))


def write_slot(payload, dev, base_rev):
    """
    写入某个设备自己的数据槽（槽级乐观锁）：
      - base_rev 与该槽当前 rev 不一致 → 拒绝（409），客户端重新拉取合并后再试
      - 一致 → 写入，该槽 rev+1，全局 rev+1
    各设备写各的槽，互相之间永远不会冲突。
    """
    with LOCK:
        d = read_data()
        slots = d.setdefault('slots', {})
        cur = slots.get(dev) or {'rev': 0, 'ts': 0, 'payload': None}
        if base_rev is not None and cur.get('rev', 0) != base_rev:
            return {'ok': False, 'conflict': True, 'rev': d.get('rev', 0),
                    'slotRev': cur.get('rev', 0), 'payload': cur.get('payload')}
        d['rev'] = d.get('rev', 0) + 1
        slots[dev] = {'rev': d['rev'], 'ts': int(time.time() * 1000), 'payload': payload}
        prune_slots(d, keep_dev=dev)
        write_file(d)
        return {'ok': True, 'rev': d['rev'], 'ts': d['ts'], 'slotRev': slots[dev]['rev']}


def write_legacy(payload, base_rev):
    """兼容 R23 旧客户端：整包替换（保留旧语义，便于混合升级期间过渡）"""
    with LOCK:
        d = read_data()
        if base_rev is not None and d.get('rev', 0) != base_rev:
            return {'ok': False, 'conflict': True, 'rev': d.get('rev', 0),
                    'payload': {'slots': d.get('slots')}}
        d['rev'] = d.get('rev', 0) + 1
        d['slots'] = {'legacy': {'rev': d['rev'], 'ts': int(time.time() * 1000), 'payload': payload}}
        write_file(d)
        return {'ok': True, 'rev': d['rev'], 'ts': d['ts']}


class Handler(SimpleHTTPRequestHandler):
    """静态文件 + 同步接口"""

    def _send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        self.end_headers()
        self.wfile.write(body)

    def _check_token(self, q):
        return q.get('token', [''])[0] == TOKEN

    def do_OPTIONS(self):
        self._send_json({'ok': True})

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)

        if u.path == '/api/ping':
            return self._send_json({'ok': True, 'name': 'qiwu7', 'rev': read_data()['rev'],
                                    'time': time.strftime('%Y-%m-%d %H:%M:%S')})

        if u.path == '/api/sync':
            if not self._check_token(q):
                return self._send_json({'ok': False, 'error': '口令不对'}, 401)
            d = read_data()
            slots = d.get('slots') or {}
            # 客户端带上各槽已知版本号（revs={设备id:版本}）→ 只回传有变化的槽，省带宽
            revs = {}
            raw_revs = q.get('revs', [''])[0]
            if raw_revs:
                try:
                    revs = json.loads(raw_revs)
                    if not isinstance(revs, dict):
                        revs = {}
                except Exception:
                    revs = {}
            if revs:
                changed = {dev: s for dev, s in slots.items()
                           if not (dev in revs and revs[dev] == s.get('rev'))}
            else:
                changed = slots
            return self._send_json({'ok': True, 'rev': d['rev'], 'ts': d['ts'], 'slots': changed,
                                    'count': len(slots),
                                    'slotsRev': {dev: s.get('rev', 0) for dev, s in slots.items()}})

        if u.path == '/api/backup':
            if not self._check_token(q):
                return self._send_json({'ok': False, 'error': '口令不对'}, 401)
            d = read_data()
            body = json.dumps(d, ensure_ascii=False).encode('utf-8')
            fn = '栖梧7班数据备份-%s.json' % time.strftime('%Y%m%d-%H%M')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            # HTTP 头只能装 ASCII：中文文件名必须按 RFC 5987 百分号编码，否则 send_header 抛 UnicodeEncodeError
            self.send_header('Content-Disposition', 'attachment; filename*=UTF-8\'\'%s' % quote(fn))
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # 其余走静态文件
        return SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)

        if u.path != '/api/sync':
            return self._send_json({'ok': False, 'error': 'not found'}, 404)

        if not self._check_token(q):
            return self._send_json({'ok': False, 'error': '口令不对'}, 401)

        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length).decode('utf-8') if length else ''
        try:
            req = json.loads(raw) if raw else {}
        except Exception as e:
            return self._send_json({'ok': False, 'error': '请求不是合法 JSON：%s' % e}, 400)

        payload = req.get('payload')
        base_rev = req.get('baseRev')
        if payload is None:
            return self._send_json({'ok': False, 'error': '缺少 payload'}, 400)

        dev = req.get('deviceId')
        if dev is not None:
            # R24 新协议：写自己的数据槽
            dev = str(dev)[:64] or 'unknown'
            r = write_slot(payload, dev, base_rev)
        else:
            # 旧协议：整包替换（兼容升级过渡期的旧客户端）
            r = write_legacy(payload, base_rev)

        if not r.get('ok'):
            # 冲突：把服务器最新版本一起返回，客户端合并后重试
            return self._send_json({'ok': False, 'conflict': True, 'rev': r.get('rev', 0),
                                    'slotRev': r.get('slotRev'),
                                    'payload': r.get('payload'),
                                    'slots': r.get('payload', {}).get('slots') if isinstance(r.get('payload'), dict) else None,
                                    'error': '数据已被其他设备更新，请合并后重试'}, 409)
        log('已同步 rev=%s（%s，来自 %s）' % (r['rev'], dev or 'legacy', self.client_address[0]))
        return self._send_json({'ok': True, 'rev': r['rev'], 'ts': r['ts'], 'slotRev': r.get('slotRev')})

    def log_message(self, fmt, *args):
        # 只在出错时打印，避免刷屏
        if '404' in (fmt % args) or '500' in (fmt % args):
            log(fmt % args)


def main():
    # 静态根目录 = 本脚本所在目录
    os.chdir(BASE_DIR)
    try:
        srv = ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    except OSError as e:
        print('端口 %s 起不来：%s\n换一个端口试试，例如：python qiwu7_server.py 9000' % (PORT, e))
        sys.exit(1)

    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = '127.0.0.1'

    print('=' * 62)
    print('  栖梧7班班级管理系统 · 校园网服务端已启动（R24 数据槽版）')
    print('=' * 62)
    print('  本机访问：   http://127.0.0.1:%s' % PORT)
    print('  局域网访问： http://%s:%s   ← 把这个地址发给老师 / 输进一体机' % (ip, PORT))
    print('  班级口令：   %s' % TOKEN)
    if TOKEN == 'qiwu7':
        print('  ' + '!' * 58)
        print('  !! 安全警告：你现在用的是【默认口令 qiwu7】')
        print('  !! 这个口令是公开的（写在启动脚本和说明文档里），')
        print('  !! 校园网内任何知道本机地址的人都能下载全班数据、')
        print('  !! 给自己加分，甚至覆盖全班记录。')
        print('  !! 强烈建议改掉（改完要重启本服务）：')
        print('  !!   Windows: 改 启动_Windows.bat 第 13 行 set QIWU7_TOKEN=你的口令')
        print('  !!   Linux:   QIWU7_TOKEN=你的口令 ./启动_Linux.sh')
        print('  ' + '!' * 58)
    print('  数据文件：   %s' % DATA_FILE)
    print('  停止服务：   按 Ctrl + C（systemd 服务用 sudo systemctl stop qiwu7）')
    print('=' * 62)
    print('  提醒：第一次打开网页后，要去「设置 / 数据 → 🌐 校园网同步」')
    print('        填上面的地址与口令，点「立即同步」，三端就通了。')
    print('=' * 62)
    sys.stdout.flush()          # 立刻显示，避免被输出缓冲吞掉
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\n已停止。')
        srv.server_close()


if __name__ == '__main__':
    main()
