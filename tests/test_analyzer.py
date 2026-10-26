import copy
import gzip
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from analyzer import analyze, load_events, write_reports

ROOT = Path(__file__).resolve().parents[1]

class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.records = load_events(ROOT / 'data/sample_cloudtrail.json')

    def test_sample_exact_results(self):
        result = analyze(self.records)
        self.assertEqual(result['summary']['analyzed_events'], 15)
        self.assertCountEqual([f['rule_id'] for f in result['findings']],
            ['NO_MFA_LOGIN', 'ROOT_ACTIVITY', 'LOGGING_CHANGE', 'ADMIN_POLICY', 'LOGIN_BURST'])
        self.assertEqual(result['summary']['severity_counts'], {'High': 4, 'Medium': 1})

    def test_benign_events_and_negative_controls(self):
        self.assertEqual(analyze(load_events(ROOT / 'data/normal_cloudtrail.json'))['findings'], [])
        self.assertEqual(analyze(self.records[-3:])['findings'], [])

    def test_failed_mutations_do_not_claim_success(self):
        mutations = copy.deepcopy(self.records[5:7])
        for e in mutations:
            e['errorCode'] = 'AccessDenied'
        self.assertEqual(analyze(mutations)['findings'], [])

    def test_service_name_collision(self):
        e = copy.deepcopy(self.records[5]); e['eventSource'] = 'other.amazonaws.com'
        self.assertEqual(analyze([e])['findings'], [])

    def test_unknown_and_federated_mfa_not_inferred(self):
        e = copy.deepcopy(self.records[3]); e['additionalEventData'] = None
        self.assertEqual(analyze([e])['findings'], [])
        e['additionalEventData'] = {'MFAUsed':'No'}; e['userIdentity']['type'] = 'AssumedRole'
        self.assertEqual(analyze([e])['findings'], [])

    def test_duplicates_and_unordered_input(self):
        result = analyze(list(reversed(self.records)) + [self.records[3]])
        self.assertEqual(result['summary']['duplicate_events'], 1)
        self.assertEqual(len(result['findings']), 5)

    def test_time_window_and_account_isolation(self):
        failures = copy.deepcopy(self.records[7:12])
        failures[-1]['eventTime'] = '2026-10-01T13:00:00Z'
        self.assertEqual(analyze(failures)['findings'], [])
        failures = copy.deepcopy(self.records[7:12])
        failures[-1]['userIdentity']['accountId'] = '999900001111'
        self.assertEqual(analyze(failures)['findings'], [])

    def test_inclusive_window_boundary(self):
        events = copy.deepcopy(self.records[7:9])
        events[0]['eventTime'] = '2026-10-01T12:00:00Z'
        events[1]['eventTime'] = '2026-10-01T12:10:00Z'
        self.assertEqual(len(analyze(events, threshold=2)['findings']), 1)

    def test_bad_records_and_nullable_fields(self):
        result = analyze([None, {}, {'eventName':'x','eventSource':'x','eventTime':'bad'}])
        self.assertEqual(result['summary']['skipped_records'], 3)
        e = copy.deepcopy(self.records[3]); e['userIdentity'] = None; e['responseElements'] = None
        self.assertEqual(analyze([e])['findings'], [])

    def test_gzip_and_invalid_envelope(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'test.json.gz'
            with gzip.open(path,'wt') as f: json.dump({'Records':self.records},f)
            self.assertEqual(len(load_events(path)),15)
            invalid=Path(d)/'bad.json'; invalid.write_text('{"Records": null}')
            with self.assertRaises(ValueError): load_events(invalid)

    def test_csv_formula_guard_and_reports(self):
        result = analyze(self.records)
        result['findings'][0]['actor'] = '=HYPERLINK("bad")'
        with tempfile.TemporaryDirectory() as d:
            write_reports(result,Path(d))
            self.assertIn("'=HYPERLINK",(Path(d)/'findings.csv').read_text())
            self.assertEqual(json.loads((Path(d)/'findings.json').read_text())['summary']['findings'],5)

    def test_cli_success_and_bad_json(self):
        with tempfile.TemporaryDirectory() as d:
            cmd=[sys.executable,str(ROOT/'analyzer.py')]
            ok=subprocess.run(cmd+[str(ROOT/'data'), '--output', d],capture_output=True,text=True)
            self.assertEqual(ok.returncode,0,ok.stderr)
            bad=Path(d)/'bad.json'; bad.write_text('{')
            fail=subprocess.run(cmd+[str(bad)],capture_output=True,text=True)
            self.assertEqual(fail.returncode,2)
            self.assertIn('Error:',fail.stderr)

    def test_unrelated_login_error_does_not_trigger_failure_burst(self):
        failures = copy.deepcopy(self.records[7:12])
        for event in failures:
            event['responseElements'] = None
            event['errorCode'] = 'AccessDenied'
        self.assertEqual(analyze(failures)['findings'], [])

    def test_explicit_failed_login_without_error_code(self):
        failures = copy.deepcopy(self.records[7:12])
        for event in failures:
            event.pop('errorCode', None)
        self.assertEqual([f['rule_id'] for f in analyze(failures)['findings']], ['LOGIN_BURST'])

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError): analyze([],threshold=0)

if __name__ == '__main__':
    unittest.main()
