"""Role projections, schemas, and bounded reversible storage for Qiwu7."""
import copy
import datetime as dt
import hashlib
import json
import re

ZONE = dt.timezone(dt.timedelta(hours=8))
RESERVED = {'__proto__', 'constructor', 'prototype'}
ID = re.compile(r'[A-Za-z0-9_-]{1,100}\Z')


class Denied(Exception):
    pass


def date_now():
    return dt.datetime.now(ZONE).date()


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value) or value in RESERVED:
        raise Denied('记录编号格式无效')


def text(value, limit=2000, required=False):
    if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
        raise Denied('文本格式或长度无效')


def number(value, low=0, high=1000000):
    if type(value) not in (int, float) or not low <= value <= high:
        raise Denied('数值范围无效')


def own(item, sid, name):
    # Legacy feedback used studentId or name instead of sid.
    owner = item.get('sid') or item.get('studentId')
    return owner == sid if owner else item.get('name') == name


def pushed(master, key, sid):
    value = master.get(key, {}).get(sid, 0)
    return bool(value and value >= master.get(key+'Tomb', {}).get(sid, 0))


def read_view(current, session):
    if session['role'] == 'teacher':
        return copy.deepcopy({'master': current['master'], 'shared': current['shared']})
    personal = session['role'] == 'personal'
    sid = session.get('sid') if personal else None
    source = current['master']
    stu = next((x for x in source['students'] if x['id'] == sid), {})
    name = stu.get('name', '')
    # Clear every non-public field explicitly, so stale client defaults cannot retain it.
    master = {k: ({} if isinstance(v, dict) else [] if isinstance(v, list) else '' if isinstance(v, str) else 0)
              for k, v in source.items()}
    for k in ['ts', 'groupCount', 'positionPoints', 'rulesContent', 'rulesBlocks', 'rulesUpdatedAt']:
        if k in source:
            master[k] = copy.deepcopy(source[k])
    master['students'] = [{k: x[k] for k in ['id', 'name', 'group', 'role'] if k in x} for x in source['students']]
    master['weekly'] = {}
    for week, snapshot in source.get('weekly', {}).items():
        result = {k: copy.deepcopy(snapshot[k]) for k in ['archivedAt', 'records'] if k in snapshot}
        result['groups'] = []
        for group in snapshot.get('groups', []):
            row = {k: copy.deepcopy(group[k]) for k in ['group', 'total', 'avg'] if k in group}
            row['members'] = [{k: copy.deepcopy(member[k]) for k in ['id', 'name', 'role', 'base', 'delta', 'score'] if k in member}
                              for member in group.get('members', [])]
            result['groups'].append(row)
        master['weekly'][week] = result
    public_settings = {'baseScore', 'lateDeduct', 'absentDeduct', 'scoreStartDate', 'holidays', 'makeupDays',
                       'attRequireCheckIn', 'sessions', 'bonusReasons', 'deductReasons', 'categories',
                       'semesterStart', 'semesterEnd', 'semesterStartDate', 'semesterEndDate', 'className'}
    master['settings'] = {k: copy.deepcopy(v) for k, v in source.get('settings', {}).items() if k in public_settings}
    master['settings']['cloud'] = {'on': True, 'url': '', 'token': ''}
    master['exams'] = []
    master['redeemedTotals'] = {}
    for order in current['shared'].get('prizeOrders', []):
        if order.get('status') == 'approved' and isinstance(order.get('cost'), (int, float)):
            key = order.get('sid')
            master['redeemedTotals'][key] = master['redeemedTotals'].get(key, 0)+order['cost']
    for key in ['pushedGrowth', 'pushedReport', 'pushedGrowthTomb', 'pushedReportTomb']:
        master[key] = {sid: source[key][sid]} if sid and sid in source.get(key, {}) else {}
    if sid and pushed(source, 'pushedReport', sid):
        for exam in source.get('exams', []):
            result = {k: copy.deepcopy(exam[k]) for k in ['id', 'name', 'date', 'subjects'] if k in exam}
            for key in ['scores', 'rich']:
                result[key] = {name: copy.deepcopy(exam[key][name])} if name in (exam.get(key) or {}) else {}
            master['exams'].append(result)
        master['reportComments'] = {name: source['reportComments'][name]} if name in source.get('reportComments', {}) else {}
    if sid and pushed(source, 'pushedGrowth', sid):
        master['growthEdits'] = {sid: source['growthEdits'][sid]} if sid in source.get('growthEdits', {}) else {}

    shared = copy.deepcopy(current['shared'])
    shared['records'] = []
    public_record = {'id', 'studentId', 'weekKey', 'type', 'amount', 'ts', 'timeStr', 'cat', 'date'}
    for item in current['shared'].get('records', []):
        if sid and (item.get('studentId') == sid or item.get('actorSid') == sid):
            shared['records'].append(copy.deepcopy(item))
        else:
            shared['records'].append({k: copy.deepcopy(v) for k, v in item.items() if k in public_record})
    for key in ['studentFeedbacks', 'nominations', 'prizeOrders']:
        shared[key] = [copy.deepcopy(x) for x in shared.get(key, []) if sid and own(x, sid, name)]
    shared['attendanceRemarks'] = [x for x in shared.get('attendanceRemarks', []) if sid and x.get('studentId') == sid]
    shared['studyLog'] = [x for x in shared.get('studyLog', []) if sid and x.get('sid') == sid]
    shared['attendance'] = {date: {sess: {sid: copy.deepcopy(entries[sid])} for sess, entries in day.items() if sid in entries}
                            for date, day in shared.get('attendance', {}).items()} if sid else {}
    # Authoritative replacement removes deleted private rows; their global tombs are unnecessary.
    shared['attTomb'] = {}
    shared['orderTomb'] = {}
    for item in shared.get('praises', []):
        if item.get('anon') and item.get('fromSid') != sid:
            item['fromSid'] = ''; item['fromName'] = ''; item['fromRole'] = 'personal'
    return {'master': master, 'shared': shared}


FIELDS = {
    'records': 'id studentId weekKey type amount reason ts timeStr source attDate attKey autoAbsent cat sub notify batchId date operator reminder actorSid eventKey',
    'studentFeedbacks': 'id studentId sid name text ts timeStr read source',
    'attendanceRemarks': 'id date session studentId text ts timeStr status',
    'studyLog': 'id sid date startTs endTs dur mode ts timeStr verified',
    'prizeOrders': 'id sid name prizeId prizeName cost ts timeStr status statusTs',
    'nominations': 'id sid name what amount why ts timeStr status statusTs approvedAmount recordId',
    'praises': 'id v fromSid fromName fromRole toSid toName reason anon ts timeStr',
    'prizes': 'id name cost stock active desc ts',
}
SHORT = {'weekKey', 'type', 'source', 'attDate', 'cat', 'sub', 'date', 'status', 'mode', 'verified', 'session'}
IDENTIFIERS = {'id', 'studentId', 'sid', 'fromSid', 'toSid', 'batchId', 'prizeId', 'recordId'}


def schema(key, item):
    if not isinstance(item, dict):
        raise Denied('记录格式无效')
    extra = set(item) - set(FIELDS[key].split())
    if extra:
        raise Denied('记录包含不允许的字段: ' + ','.join(sorted(extra))[:200])
    identifier(item.get('id'))
    for field, value in item.items():
        if field in IDENTIFIERS:
            if value not in ('', None): identifier(value)
        elif field in SHORT:
            text(value, 100)
        elif field in {'reason', 'text', 'what', 'why', 'desc'}:
            text(value, 2000)
        elif field in {'name', 'operator', 'fromName', 'toName', 'prizeName', 'timeStr'}:
            text(value, 100)
        elif field in {'ts', 'startTs', 'endTs', 'statusTs'}:
            number(value, 0, 1e15)
        elif field in {'amount', 'cost', 'dur', 'approvedAmount', 'stock', 'v'}:
            if value is not None: number(value, -1 if field == 'stock' else 0)
        elif field in {'read', 'notify', 'reminder', 'active', 'anon'}:
            if not isinstance(value, bool): raise Denied('开关格式无效')
        elif field == 'eventKey':
            text(value, 64)
    if key == 'records':
        if item.get('type') not in ['bonus', 'deduct']: raise Denied('积分类型无效')
        number(item.get('amount'), 0.01)
        if not re.fullmatch(r'\d{4}-W\d{2}', item.get('weekKey', '')): raise Denied('积分周次无效')
    if key == 'prizes':
        text(item.get('name'), 100, True); number(item.get('cost'), 0.01)


def scoring_key(item, actor, today=None):
    today = today or date_now()
    year, week, _ = today.isocalendar()
    if item.get('weekKey') != f'{year}-W{week:02d}' or item.get('date', today.isoformat()) != today.isoformat():
        raise Denied('学生只能登记今天、本周的积分；历史补录请联系老师')
    item['date'] = today.isoformat()
    # The batch ID is client controlled and cannot serve as the business deduplication key.
    business = [actor, item['studentId'], item['date'], item['type'], item.get('cat', ''),
                item.get('sub', '').strip(), item.get('reason', '').strip()]
    return hashlib.sha256(json.dumps(business, ensure_ascii=False).encode()).hexdigest()


def reverse_delta(before, after):
    """Restore old rows and remove added IDs; unchanged arrays are never copied."""
    result = {'format': 3, 'before': {k: v for k, v in before.items() if k not in ['master', 'shared']}, 'shared': {}}
    if before['master'] != after['master']: result['master'] = before['master']
    for key, old in before['shared'].items():
        new = after['shared'][key]
        if new == old: continue
        if isinstance(old, list):
            a = {x['id']: x for x in old}; b = {x['id']: x for x in new}
            result['shared'][key] = {'rows': [{'index': i, 'value': x} for i, x in enumerate(old) if b.get(x['id']) != x],
                                     'remove': [rid for rid in b if rid not in a]}
            if [rid for rid in a if rid in b] != [rid for rid in b if rid in a]:
                result['shared'][key]['order'] = list(a)
        else:
            # Maps (including attendance) are stored only for changed top-level keys.
            result['shared'][key] = {'restore': {k: v for k, v in old.items() if new.get(k) != v},
                                     'remove': [k for k in new if k not in old]}
    return result


def restore_delta(current, delta):
    if delta.get('format') != 3 or current['rev'] != delta['before']['rev']+1:
        raise ValueError('备份版本链不连续，拒绝恢复')
    result = copy.deepcopy(current)
    result.update(delta['before'])
    if 'master' in delta: result['master'] = copy.deepcopy(delta['master'])
    for key, change in delta['shared'].items():
        if 'rows' in change:
            removed = set(change['remove']) | {x['value']['id'] for x in change['rows']}
            rows = [x for x in result['shared'][key] if x['id'] not in removed]
            for x in sorted(change['rows'], key=lambda x: x['index']):
                rows.insert(x['index'], copy.deepcopy(x['value']))
            if 'order' in change:
                by_id = {x['id']: x for x in rows}; rows = [by_id[rid] for rid in change['order']]
            result['shared'][key] = rows
        else:
            mapping = result['shared'][key]
            for k in change['remove']: mapping.pop(k, None)
            mapping.update(copy.deepcopy(change['restore']))
    return result
