"""Inert source fixtures; the scanner never imports or executes them."""
import json
from pathlib import Path
import tempfile
import unittest

from decrypto_python_checks import check_python_security
from decrypto_crypto_checks import scan_repo_for_crypto_issues


class TestPythonSecurityChecks(unittest.TestCase):
    def rules(self, source):
        return {f['rule'] for f in check_python_security(source, 'fixture.py')}

    def test_pickle_import_aliases(self):
        for source in ('import pickle\npickle.loads(data)',
                       'import pickle as p\np.load(stream)',
                       'from pickle import loads as decode\ndecode(data)',
                       'import dill\ndill.loads(data)'):
            with self.subTest(source=source):
                self.assertEqual(self.rules(source), {'PY-UNSAFE-DESERIALIZATION'})

    def test_safe_data_parsers_not_flagged(self):
        self.assertEqual(self.rules('import json, ast, yaml\njson.loads(data)\nast.literal_eval(data)\nyaml.safe_load(data)'), set())

    def test_yaml_unsafe_and_unknown_loaders(self):
        for call in ('yaml.load(data)', 'yaml.load(data, Loader=yaml.Loader)',
                     'yaml.unsafe_load(data)', 'yaml.load_all(data, Loader=loader)'):
            with self.subTest(call=call):
                self.assertIn('PY-UNSAFE-YAML', self.rules('import yaml\n' + call))

    def test_yaml_safe_loader_alias_and_positional(self):
        self.assertEqual(self.rules('import yaml as y\nfrom yaml import SafeLoader as S\ny.load(data, Loader=S)\ny.load_all(data, y.CSafeLoader)'), set())

    def test_explicit_shell_execution(self):
        for call in ('subprocess.run(command, shell=True)', 'subprocess.Popen(command, shell=True)',
                     'subprocess.getoutput(command)', 'os.system(command)', 'os.popen(command)'):
            with self.subTest(call=call):
                self.assertIn('PY-SHELL-EXECUTION', self.rules('import subprocess, os\n' + call))

    def test_shell_false_or_default_is_not_flagged(self):
        self.assertEqual(self.rules('import subprocess\nsubprocess.run(["tool", arg], shell=False)\nsubprocess.run(["tool", arg])'), set())

    def test_dynamic_evaluation_and_alias(self):
        self.assertEqual(self.rules('eval(text)\nexec(text)\nfrom builtins import eval as evaluate\nevaluate(text)'), {'PY-DYNAMIC-EVALUATION'})

    def test_shadowed_imports_and_builtins_are_ignored(self):
        for source in ('import pickle\npickle = custom\npickle.loads(data)',
                       'def f(pickle, eval):\n    pickle.loads(data)\n    eval(data)',
                       'def eval(value):\n    return value\neval(data)',
                       'import pickle\ndef f(pickle):\n    pickle.loads(data)'):
            with self.subTest(source=source):
                self.assertEqual(self.rules(source), set())

    def test_import_does_not_leak_between_functions(self):
        source = 'def f():\n    import pickle as p\n    p.loads(data)\ndef g():\n    p.loads(data)\n'
        entries = check_python_security(source, 'fixture.py')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['evidence']['line'], 3)

    def test_nested_function_resolves_module_import(self):
        self.assertIn('PY-UNSAFE-DESERIALIZATION', self.rules('import pickle\ndef f():\n    return pickle.loads(data)'))

    def test_comments_strings_and_similar_methods_not_flagged(self):
        self.assertEqual(self.rules('# eval(data)\ntext = "pickle.loads(data)"\ncustom.loads(data)'), set())

    def test_report_metadata_and_privacy(self):
        source = 'import pickle\npickle.loads(b"private-marker"); eval("another-marker")\n'
        entries = check_python_security(source, 'fixture.py')
        self.assertEqual(len(entries), 2)
        self.assertEqual(len({f['id'] for f in entries}), 2)
        self.assertNotIn('private-marker', json.dumps(entries))
        self.assertNotIn('another-marker', json.dumps(entries))
        for entry in entries:
            self.assertNotEqual(entry['taxonomy']['category'], 'uncategorized')
            self.assertIn('UNCONFIRMED', entry['status'])

    def test_repository_integration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'sample.py').write_text('import pickle\npickle.loads(data)')
            report = scan_repo_for_crypto_issues(root)
            self.assertIn('PY-UNSAFE-DESERIALIZATION', {f['rule'] for f in report['findings']})
            self.assertIn('unsafe-deserialization', report['findings_by_category'])

    def test_invalid_python_has_explicit_partial_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'bad.py').write_text('md5 = (')
            report = scan_repo_for_crypto_issues(root)
            self.assertEqual(report['meta']['files_inspected'], 1)
            self.assertIn('regex checks only', report['meta']['skipped'][0]['reason'])
            self.assertTrue(report['findings'])
