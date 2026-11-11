import unittest
from guarddesk.remote_quality import options,select,NATIVE,UNAVAILABLE,FEATURES

class QualityDefaultsTest(unittest.TestCase):
    def native(self,**changes):return {'wire':1,'cohort_sha256':'a'*64,'features':list(FEATURES),**changes}
    def test_matching_full_agent_defaults_to_realtime_not_two_fps(self):
        choices=options(True,self.native(),'a'*64)
        self.assertEqual(select('清晰 · 原始解析度／最高 2 FPS',choices),NATIVE)
        self.assertIn('清晰 · 原始解析度／最高 2 FPS',choices)
    def test_explicit_operator_choice_is_preserved(self):
        choices=options(True,self.native(),'a'*64)
        for value in choices:self.assertEqual(select(value,choices,manual=True),value)
    def test_mixed_cohort_and_missing_features_never_offer_native(self):
        for native,local in [(self.native(cohort_sha256='b'*64),'a'*64),(self.native(wire=2),'a'*64),(self.native(features=[]),'a'*64),(self.native(),None)]:
            self.assertNotIn(NATIVE,options(True,native,local))
            self.assertEqual(select(NATIVE,options(True,native,local,native_only=True)),UNAVAILABLE)
    def test_legacy_only_keeps_previous_supported_selection(self):
        choices=options(True,None,None)
        self.assertEqual(select('清晰 · 原始解析度／最高 2 FPS',choices),choices[0])
        self.assertNotIn(NATIVE,choices)
    def test_trial_never_falls_back_to_legacy(self):
        self.assertEqual(options(True,self.native(),'a'*64,native_only=True),[NATIVE])
        self.assertEqual(options(True,None,None,native_only=True),[])

if __name__=='__main__':unittest.main()
