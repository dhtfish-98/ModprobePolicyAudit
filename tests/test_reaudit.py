import unittest,json,tempfile,subprocess,sys
from pathlib import Path
from modprobe_policy_audit import analyze
from modprobe_policy_audit.common import InputError
PROJECT=Path(__file__).resolve().parents[1]
class ReauditTests(unittest.TestCase):
    def good(self):return json.loads((PROJECT/'examples/good.json').read_text())
    def cli(self,snapshot,expected):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'case.json';p.write_text(json.dumps(snapshot))
            r=subprocess.run([sys.executable,'-m','modprobe_policy_audit',str(p)],capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,expected,r.stderr)
            self.assertNotIn('Traceback',r.stderr)
            return json.loads(r.stdout)
    def test_global_glob_spellings_cannot_pass(self):
        for pattern in ('*','**','***','*?*','?**','**?'):
            s=self.good();s['files']['/etc/modprobe.d/99-policy.conf']+='\nalias '+pattern+' helper'
            self.assertEqual(analyze(s)['status'],'FAIL');self.assertEqual(self.cli(s,1)['status'],'FAIL')
    def test_scoped_alias_not_global(self):
        s=self.good();s['files']['/etc/modprobe.d/99-policy.conf']+='\nalias known_prefix* helper'
        self.assertEqual(analyze(s)['status'],'PASS');self.assertEqual(self.cli(s,0)['status'],'PASS')
    def test_unmodelled_complex_or_unanchored_globs_are_open(self):
        for pattern in ('[a-zA-Z0-9_-]*','[!x]*','*suffix','?*?*','pci:[0-9]*'):
            s=self.good();s['files']['/etc/modprobe.d/99-policy.conf']+='\nalias '+pattern+' helper'
            self.assertEqual(analyze(s)['status'],'OPEN');self.assertEqual(self.cli(s,3)['status'],'OPEN')
    def test_hardware_literal_prefix_glob_is_bounded(self):
        s=self.good();s['files']['/etc/modprobe.d/99-policy.conf']+='\nalias pci:v00001234d*sv*sd*bc*sc*i* helper'
        self.assertEqual(analyze(s)['status'],'PASS');self.assertEqual(self.cli(s,0)['status'],'PASS')
