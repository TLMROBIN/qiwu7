"""Attack-boundary regressions using synthetic isolated state only."""
import copy
import json
import pathlib
import tempfile
import unittest
from unittest import mock
import test_security as fixture
from qiwu7_security import read_view, reverse_delta, restore_delta


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.harness = type('IsolatedFixture', (fixture.SecurityTests,), {})
        self.harness.setUpClass()
        self.addCleanup(self.harness.tearDownClass)
        self.api = self.harness()
        self.teacher, self.tc = self.api.login()
        self.student, self.sc = self.api.login('student', 'personal')

    def sync(self, opener, csrf, role, change):
        body = self.api.payload(opener, role)
        change(body['payload'])
        return self.api.request('/api/sync', body, opener, csrf)

    def seed_private(self):
        def seed(p):
            p['master'].update({'weeklyNotes': {'private-note': 'SECRET_NOTE'}, 'growthEdits': {'s2': 'SECRET_GROWTH'},
                                'pushedReport': {'s1': 1}, 'pushedReportTomb': {}, 'pushedGrowth': {}, 'pushedGrowthTomb': {}})
            p['master']['exams'] = [{'id': 'exam', 'name': 'exam', 'date': '2026-10', 'subjects': ['physics'],
                                     'scores': {'普通学生': {'physics': 80}, '课代表': {'physics': 90}},
                                     'rich': {'普通学生': {'gr': 20}, '课代表': {'gr': 10}}, 'private': 'SECRET_EXAM_META'}]
            p['shared']['studentFeedbacks'] = [{'id': 'private-fb', 'sid': 's2', 'name': '课代表', 'text': 'SECRET_FEEDBACK', 'read': False}]
            p['shared']['nominations'] = [{'id': 'private-n', 'sid': 's2', 'name': '课代表', 'what': 'SECRET_APPLICATION', 'why': 'x', 'amount': 1, 'status': 'pending'}]
            p['shared']['studyLog'] = [{'id': 'private-study', 'sid': 's2', 'date': fixture.server.date_now().isoformat(), 'dur': 1}]
        self.assertEqual(self.sync(self.teacher, self.tc, 'teacher', seed)[0], 200)

    def test_private_read_projection_and_noop_preserve_hidden_state(self):
        self.seed_private()
        body = self.api.payload(self.student, 'personal')
        raw = json.dumps(body, ensure_ascii=False)
        self.assertNotIn('SECRET_', raw)
        _, response = self.api.request('/api/sync', opener=self.student)
        master = response['slots']['authoritative']['payload']['master']
        self.assertEqual(set(master['exams'][0]['scores']), {'普通学生'})
        self.assertEqual(set(master['exams'][0]['rich']), {'普通学生'})
        for key in ['nominations', 'studentFeedbacks', 'studyLog']:
            self.assertEqual(body['payload']['shared'][key], [])
        self.assertEqual(self.api.request('/api/sync', body, self.student, self.sc)[0], 200)
        _, teacher = self.api.request('/api/sync', opener=self.teacher)
        self.assertIn('SECRET_FEEDBACK', json.dumps(teacher))
        _, html = self.api.request('/', opener=self.student)
        self.assertNotIn('SECRET_', html)
        self.assertNotIn('EMBEDDED_EXAMS', html)
        self.assertNotIn('BASELINE_DATA', html)
        # Withdrawing a report removes the actual score payload, not only the UI flag.
        self.assertEqual(self.sync(self.teacher, self.tc, 'teacher', lambda p: p['master']['pushedReportTomb'].update({'s1': 2}))[0], 200)
        _, response = self.api.request('/api/sync', opener=self.student)
        self.assertEqual(response['slots']['authoritative']['payload']['master']['exams'], [])

    def test_classroom_readonly_all_shared_fields(self):
        self.seed_private()
        room, csrf = self.api.login('teacher', 'classroom')
        original = self.api.payload(room, 'classroom')
        self.assertNotIn('SECRET_', json.dumps(original))
        self.assertEqual(self.api.request('/api/sync', original, room, csrf)[0], 200)
        for key in fixture.server.ARRAYS:
            with self.subTest(field=key):
                body = copy.deepcopy(original)
                body['payload']['shared'][key].append({'id': 'forged'})
                self.assertEqual(self.api.request('/api/sync', body, room, csrf)[0], 403)
        body = copy.deepcopy(original); body['payload']['shared']['tomb']['private-record'] = 1
        self.assertEqual(self.api.request('/api/sync', body, room, csrf)[0], 403)

    def test_student_filtered_echo_does_not_overwrite_private_record_fields(self):
        def seed(p):
            p['shared']['records'].append({'id': 'private-reason', 'studentId': 's2', 'weekKey': '2026-W43', 'type': 'deduct', 'amount': 1, 'reason': 'SECRET_REASON'})
        self.assertEqual(self.sync(self.teacher, self.tc, 'teacher', seed)[0], 200)
        body = self.api.payload(self.student, 'personal')
        self.assertNotIn('SECRET_REASON', json.dumps(body))
        self.assertEqual(self.api.request('/api/sync', body, self.student, self.sc)[0], 200)
        teacher = self.api.payload(self.teacher, 'teacher')
        self.assertEqual(teacher['payload']['shared']['records'][0]['reason'], 'SECRET_REASON')
        body['payload']['shared']['records'][0]['amount'] = 99
        self.assertEqual(self.api.request('/api/sync', body, self.student, self.sc)[0], 403)

    def test_scoring_duplicate_history_and_schema_attacks(self):
        rep, csrf = self.api.login('representative', 'personal')
        valid = {'id': 'valid', 'studentId': 's1', 'weekKey': fixture.server.date_now().strftime('%G-W%V'), 'type': 'bonus', 'amount': 1, 'cat': '作业', 'reason': 'one assignment', 'batchId': 'safe-batch'}
        for field, value in [('batchId', '__proto__'), ('batchId', '"><b>AUDIT</b>'), ('id', '"><b>AUDIT</b>'), ('sub', {}), ('weekKey', '2020-W01'), ('date', '2020-01-01'), ('unexpected', 'x')]:
            with self.subTest(field=field, value=value):
                attack = {**valid, field: value}
                self.assertEqual(self.sync(rep, csrf, 'personal', lambda p: p['shared']['records'].append(attack))[0], 403)
        self.assertEqual(self.sync(rep, csrf, 'personal', lambda p: p['shared']['records'].append(valid))[0], 200)
        replay = {**valid, 'id': 'new-id', 'batchId': 'new-batch'}
        self.assertEqual(self.sync(rep, csrf, 'personal', lambda p: p['shared']['records'].append(replay))[0], 403)
        # Distinct assignments remain possible.
        distinct = {**valid, 'id': 'second', 'reason': 'different assignment'}
        self.assertEqual(self.sync(rep, csrf, 'personal', lambda p: p['shared']['records'].append(distinct))[0], 200)

    def test_forged_duration_and_short_server_timer(self):
        forged = {'id': 'fake', 'sid': 's1', 'date': fixture.server.date_now().isoformat(), 'dur': 1440, 'startTs': 0, 'endTs': 1}
        self.assertEqual(self.sync(self.student, self.sc, 'personal', lambda p: p['shared']['studyLog'].append(forged))[0], 403)
        status, data = self.api.request('/api/study', {'action': 'start', 'dur': 99999, 'mode': 'free'}, self.student, self.sc)
        self.assertEqual(status, 200)
        timer = data['study']['id']
        for action in ['pause', 'resume', 'stop', 'stop']:
            status, data = self.api.request('/api/study', {'action': action, 'id': timer, 'dur': 99999}, self.student, self.sc)
            self.assertEqual(status, 200)
        self.assertIsNone(data['study'])
        self.assertEqual(self.api.payload(self.student, 'personal')['payload']['shared']['studyLog'], [])
        self.assertEqual(self.api.request('/api/study', {'action': 'start'}, self.teacher, self.tc)[0], 403)

    def test_bounded_text_and_incremental_backups(self):
        def feedback(rid, text):
            return {'id': rid, 'name': '普通学生', 'text': text, 'read': False}
        self.assertEqual(self.sync(self.student, self.sc, 'personal', lambda p: p['shared']['studentFeedbacks'].append(feedback('large', 'x'*499000)))[0], 403)
        for n in range(3):
            self.assertEqual(self.sync(self.student, self.sc, 'personal', lambda p, n=n: p['shared']['studentFeedbacks'].append(feedback('small-'+str(n), 'x'*1000)))[0], 200)
        backups = self.harness.private/'backups'
        self.assertEqual(len(list(backups.glob('state-*.json'))), 1)
        deltas = list(backups.glob('delta-*.json'))
        self.assertEqual(len(deltas), 3)
        self.assertTrue(all(p.stat().st_size < 1000 for p in deltas))

    def test_write_rate_limit(self):
        body = self.api.payload(self.student, 'personal')
        for _ in range(20):
            self.assertEqual(self.api.request('/api/sync', body, self.student, self.sc)[0], 200)
        self.assertEqual(self.api.request('/api/sync', body, self.student, self.sc)[0], 429)

    def test_logout_revokes_session_and_clears_site_data(self):
        req = fixture.urllib.request.Request(self.harness.origin+'/api/auth/logout', data=b'{}', headers={'Content-Type': 'application/json', 'Origin': self.harness.origin, 'X-Qiwu7-CSRF': self.sc})
        response = self.student.open(req)
        self.assertIn('storage', response.headers['Clear-Site-Data'])
        self.assertEqual(self.api.request('/api/auth/session', opener=self.student)[0], 401)


class StorageAndTimerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.server = fixture.server
        initial = {'format': 2, 'epoch': 'unit', 'rev': 1, 'ts': 1, 'master': {'students': [{'id': 's1', 'name': 'student', 'role': '组员'}]}, 'shared': {k: [] for k in self.server.ARRAYS}}
        self.patch = mock.patch.multiple(self.server, PRIVATE=pathlib.Path(self.tmp.name), CURRENT=initial, STUDY={}, create=True)
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.s = {'sid': 's1', 'role': 'personal', 'account': 'test'}

    def test_timer_pause_elapsed_and_idempotent_completion(self):
        server = self.server
        stamp = 1793188800000
        with mock.patch.object(server, 'now', return_value=stamp):
            timer = server.study_action({'action': 'start'}, self.s, '127.0.0.1')['id']
        with mock.patch.object(server, 'now', return_value=stamp+61000):
            server.study_action({'action': 'pause', 'id': timer}, self.s, '127.0.0.1')
        with mock.patch.object(server, 'now', return_value=stamp+361000):
            server.study_action({'action': 'resume', 'id': timer}, self.s, '127.0.0.1')
        with mock.patch.object(server, 'now', return_value=stamp+422000):
            server.study_action({'action': 'stop', 'id': timer}, self.s, '127.0.0.1')
            rev = server.CURRENT['rev']
            server.study_action({'action': 'stop', 'id': timer}, self.s, '127.0.0.1')
        self.assertEqual(server.CURRENT['rev'], rev)
        rows = server.CURRENT['shared']['studyLog']
        self.assertEqual(sum(x['dur'] for x in rows), 2)
        self.assertEqual(rows[0]['verified'], 'server-elapsed')
        self.assertEqual(json.loads((server.PRIVATE/'study.json').read_text()), {})

    def test_storage_full_rejects_without_changing_current_state(self):
        candidate = copy.deepcopy(self.server.CURRENT); candidate['ts'] += 1
        before = copy.deepcopy(self.server.CURRENT)
        with mock.patch.object(self.server, 'MAX_ARCHIVE', 0):
            with self.assertRaises(self.server.Capacity):
                self.server.commit(candidate, self.s, '127.0.0.1')
        self.assertEqual(self.server.CURRENT, before)
        self.assertFalse((self.server.PRIVATE/'state.json').exists())

    def test_delta_roundtrip_preserves_order_and_private_maps(self):
        before=copy.deepcopy(self.server.CURRENT)
        before['shared']['records']=[{'id': 'a', 'amount': 1}, {'id': 'b', 'amount': 2}, {'id': 'c', 'amount': 3}]
        before['shared']['attendance']={'old': {'morning': {'s1': {'time': '07:00'}}}}
        after=copy.deepcopy(before); after['rev']+=1; after['master']['ts']=22
        after['shared']['records']=[{'id': 'c', 'amount': 4}, {'id': 'a', 'amount': 1}, {'id': 'new', 'amount': 5}]
        after['shared']['attendance']={'new': {}}
        self.assertEqual(restore_delta(after,reverse_delta(before,after)),before)
        with self.assertRaises(ValueError):restore_delta(before,reverse_delta(before,after))

    def test_untrusted_forwarded_proto_does_not_enable_secure_transport(self):
        handler = object.__new__(self.server.Handler)
        handler.connection = object(); handler.client_address = ('10.50.1.10', 1)
        handler.headers = {'Host': '10.50.159.62:18090', 'X-Forwarded-Proto': 'https'}
        self.assertFalse(handler.encrypted())
        self.assertFalse(handler.transport_allowed())


if __name__ == '__main__':
    unittest.main()
