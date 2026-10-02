import unittest
from modprobe_policy_audit import analyze
from modprobe_policy_audit.common import InputError

class ModTests(unittest.TestCase):
    def good(self):return {'files':{'/etc/modprobe.d/99-policy.conf':'blacklist old-fs\ninstall old_fs /bin/false'},'disabled_modules':['old-fs'],'loaded_modules':[]}
    def test_explicit_policy(self):self.assertEqual(analyze(self.good())['status'],'PASS')
    def test_blacklist_is_not_load_block(self):
        s=self.good();s['files']['/etc/modprobe.d/99-policy.conf']='blacklist old_fs';self.assertEqual(analyze(s)['status'],'FAIL')
    def test_loaded_disabled_module(self):
        s=self.good();s['loaded_modules']=['old_fs'];self.assertEqual(analyze(s)['status'],'FAIL')
    def test_higher_priority_filename(self):
        s=self.good();s['files']['/usr/lib/modprobe.d/99-policy.conf']='install old_fs /bin/evil';self.assertEqual(analyze(s)['status'],'PASS')
    def test_softdep_precedence(self):
        s=self.good();s['files']['/etc/modprobe.d/99-policy.conf']+='\nsoftdep old_fs pre: helper';self.assertEqual(analyze(s)['status'],'FAIL')
    def test_alias_scope(self):
        s=self.good();s['files']['/etc/modprobe.d/99-policy.conf']+='\nalias * old_fs';self.assertEqual(analyze(s)['status'],'FAIL')
    def test_options_metadata_open(self):
        s=self.good();s['files']['/etc/modprobe.d/99-policy.conf']+='\noptions helper secret_mode=1';self.assertEqual(analyze(s)['status'],'OPEN')
    def test_shell_compound_not_safe_stub(self):
        s=self.good();s['files']['/etc/modprobe.d/99-policy.conf']='blacklist old_fs\ninstall old_fs /bin/false; /bin/true';self.assertEqual(analyze(s)['status'],'FAIL')
    def test_dependency_cycle(self):
        s=self.good();s['files']['/etc/modprobe.d/99-policy.conf']+='\nweakdep a b\nweakdep b a';self.assertEqual(analyze(s)['status'],'FAIL')
    def test_no_loaded_observation(self):
        s=self.good();s.pop('loaded_modules');self.assertEqual(analyze(s)['status'],'OPEN')
    def test_wrong_schema(self):
        with self.assertRaises(InputError):analyze({'files':{},'disabled_modules':'x'})
    def test_too_deep_graph(self):
        s=self.good();s['files']['/etc/modprobe.d/99-policy.conf']+='\n'+'\n'.join('weakdep m'+str(i)+' m'+str(i+1) for i in range(35))
        with self.assertRaises(InputError):analyze(s)
