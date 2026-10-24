import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

from agent_permit import Context, Denied, Guard, PolicyError, loads

ROOT = Path(__file__).resolve().parents[1]


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / 'examples/policy.json').read_text())
        self.guard = Guard(self.policy)
        self.context = Context('support-agent', 'acme')
        self.args = {'collection': 'public-help', 'query': 'hello', 'limit': 5}

    def decision(self, args=None, context=None, tool='search_knowledge'):
        return self.guard.evaluate(tool, self.args if args is None else args, context or self.context)

    def test_allowed(self):
        self.assertTrue(self.decision().allowed)

    def test_unknown_tool(self):
        self.assertEqual(self.decision(tool='shell').code, 'unknown_tool')

    def test_identity_isolation(self):
        for context in [Context('other', 'acme'), Context('support-agent', 'other')]:
            with self.subTest(context=context):
                self.assertFalse(self.decision(context=context).allowed)

    def test_argument_abuse(self):
        for key, value in [('collection', 'customer-secrets'), ('collection', 'public-help/../secrets'),
                           ('limit', True), ('limit', 0), ('limit', 11), ('limit', 1.0),
                           ('query', 'x' * 501), ('query', {}), ('query', None)]:
            with self.subTest(key=key, value=str(value)[:30]):
                self.assertFalse(self.decision({**self.args, key: value}).allowed)

    def test_boundaries(self):
        for limit in [1, 10]:
            self.assertTrue(self.decision({**self.args, 'limit': limit, 'query': 'x' * 500}).allowed)

    def test_shape(self):
        for args in [{}, {**self.args, 'approved': True}, {'query': 'hi'}, [], None]:
            with self.subTest(args=args):
                self.assertFalse(self.guard.evaluate('search_knowledge', args, self.context).allowed)

    def test_context_types(self):
        for context in [None, {}, Context([], 'acme'), Context('support-agent', [])]:
            self.assertFalse(self.guard.evaluate('search_knowledge', self.args, context).allowed)

    def test_invalid_tool_type(self):
        self.assertFalse(self.decision(tool=[]).allowed)

    def test_policy_snapshot(self):
        digest = self.guard.policy_digest
        self.policy['tools']['search_knowledge']['principals'].append('intruder')
        self.assertFalse(self.decision(context=Context('intruder', 'acme')).allowed)
        self.assertEqual(self.guard.policy_digest, digest)

    def test_digest_is_stable(self):
        self.assertEqual(self.guard.policy_digest, Guard(copy.deepcopy(self.policy)).policy_digest)

    def test_policy_errors(self):
        variants = [None, {}, {**self.policy, 'typo': True}, {**self.policy, 'version': True},
                    {**self.policy, 'tools': {}}]
        for field, value in [('principals', '*'), ('tenants', []), ('typo', True), ('arguments', [])]:
            p = copy.deepcopy(self.policy)
            p['tools']['search_knowledge'][field] = value
            variants.append(p)
        for p in variants:
            with self.subTest(policy=p), self.assertRaises(PolicyError):
                Guard(p)

    def test_bad_constraints(self):
        specs = [{'type': 'number'}, {'type': 'string'}, {'type': 'string', 'max_length': True},
                 {'type': 'integer', 'minimum': 10, 'maximum': 1},
                 {'type': 'boolean', 'minimum': 0},
                 {'type': 'string', 'max_length': 2, 'enum': ['long']},
                 {'type': 'integer', 'minimum': 0, 'maximum': 1, 'enum': [True]},
                 {'type': 'boolean', 'enum': []}]
        for spec in specs:
            p = copy.deepcopy(self.policy)
            p['tools']['search_knowledge']['arguments'] = {'value': spec}
            with self.subTest(spec=spec), self.assertRaises(PolicyError):
                Guard(p)

    def test_boolean_argument(self):
        p = copy.deepcopy(self.policy)
        p['tools']['search_knowledge']['arguments'] = {'enabled': {'type': 'boolean', 'enum': [False]}}
        guard = Guard(p)
        for value, expected in [(False, True), (True, False), (0, False)]:
            self.assertEqual(guard.evaluate('search_knowledge', {'enabled': value}, self.context).allowed, expected)

    def test_strict_json(self):
        for text in ['{"a":1,"a":2}', '{"x": NaN}', '{"x": Infinity}', '[' * 2000, 'x' * 65537]:
            with self.subTest(text=text[:30]), self.assertRaises(PolicyError):
                loads(text)

    def test_dispatch_and_audit(self):
        events = []
        def handler(**args):
            self.assertEqual(len(events), 1)
            self.assertEqual(args, self.args)
            return 'result'
        self.assertEqual(self.guard.invoke('search_knowledge', self.args, self.context,
                                          {'search_knowledge': handler}, events.append), 'result')
        self.assertTrue(events[0]['allowed'])
        self.assertNotIn('hello', json.dumps(events))
        self.assertNotIn('acme', json.dumps(events))

    def test_denial_never_dispatches(self):
        events, calls = [], []
        with self.assertRaises(Denied):
            self.guard.invoke('shell', {}, self.context, {'shell': lambda: calls.append(1)}, events.append)
        self.assertEqual(calls, [])
        self.assertFalse(events[0]['allowed'])

    def test_missing_handler(self):
        events = []
        with self.assertRaisesRegex(Denied, 'handler_missing'):
            self.guard.invoke('search_knowledge', self.args, self.context, {}, events.append)
        self.assertFalse(events[0]['allowed'])

    def test_audit_failure_blocks_execution(self):
        calls = []
        def broken(event):
            raise OSError('disk full')
        with self.assertRaises(OSError):
            self.guard.invoke('search_knowledge', self.args, self.context,
                              {'search_knowledge': lambda **kw: calls.append(1)}, broken)
        self.assertEqual(calls, [])

    def test_input_mutation_during_audit(self):
        def audit(event):
            self.args['collection'] = 'customer-secrets'
        result = self.guard.invoke('search_knowledge', self.args, self.context,
                                   {'search_knowledge': lambda **kw: kw['collection']}, audit)
        self.assertEqual(result, 'public-help')

    def test_handler_error_not_retried(self):
        calls = []
        def broken(**kw):
            calls.append(1)
            raise RuntimeError('upstream')
        with self.assertRaises(RuntimeError):
            self.guard.invoke('search_knowledge', self.args, self.context,
                              {'search_knowledge': broken}, lambda event: None)
        self.assertEqual(calls, [1])

    def test_cli(self):
        for filename, code in [('allowed.json', 0), ('denied.json', 2), ('missing.json', 3)]:
            result = subprocess.run([sys.executable, '-m', 'agent_permit', '--policy', 'examples/policy.json',
                                     '--request', 'examples/' + filename, '--principal', 'support-agent',
                                     '--tenant', 'acme'], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, code, result.stderr)
            self.assertIsInstance(json.loads(result.stdout or result.stderr), dict)


if __name__ == '__main__':
    unittest.main()
