"""Bounded decoder examples, not a real Word/Office integration acceptance."""
import unittest
from unittest.mock import Mock
from guarddesk.agent import Agent
from guarddesk.document_io import ReadObserver
from guarddesk.windows_watch import NOTIFY_FILTER, RenamePairs


class WordFlowTest(unittest.TestCase):
    def test_open_reads_are_one_observation_and_writes_are_not_modifications(self):
        seen = []
        observer = ReadObserver(lambda details, occurred: seen.append(details))
        base = {'path': r'C:\Docs\report.docx', 'pid': 123, 'open_id': 5,
                'status': 0, 'occurred': 1000, 'bytes': 4096}
        for op in ('open', 'read', 'read', 'write'):
            observer.feed({**base, 'op': op})
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]['evidence'], 'completed_native_read')
        self.assertIsNone(seen[0]['user'])
        self.assertFalse(seen[0]['human_read_confirmed'])

    def test_disabled_modified_event_never_opens_database(self):
        agent = Agent.__new__(Agent)
        agent.db = Mock(side_effect=AssertionError('must not persist stopped event'))
        self.assertIsNone(agent.queue('file.modified', {'path': r'C:\Docs\report.docx'}))
        agent.db.assert_not_called()

    def test_replace_save_name_notifications_remain_separate_not_a_content_edit(self):
        # Conditional input: if an editor uses a temp file and replacement rename.
        events = RenamePairs().consume([
            (1, r'C:\Docs\~wrd1.tmp'), (2, r'C:\Docs\report.docx'),
            (4, r'C:\Docs\~wrd1.tmp'), (5, r'C:\Docs\report.docx')], now=1)
        self.assertEqual([kind for kind, _ in events],
                         ['file.created', 'file.deleted', 'file.renamed'])
        self.assertEqual(events[-1][1]['destination_path'], r'C:\Docs\report.docx')
        self.assertTrue(all('user' not in details for _, details in events))
        self.assertEqual(NOTIFY_FILTER, 0x1)
        self.assertEqual(RenamePairs().consume([(3, r'C:\Docs\report.docx')]), [])

    def test_incomplete_names_are_evidence_not_a_completed_rename(self):
        pairs = RenamePairs()
        events = pairs.consume([(4, r'C:\Docs\old.docx'), (1, r'C:\Docs\other.docx')], now=1)
        self.assertEqual([kind for kind, _ in events], ['file.rename_from', 'file.created'])
        self.assertEqual(events[0][1]['correlation'], 'unpaired_old_name')
        self.assertNotIn('destination_path', events[0][1])

    def test_folder_notifications_do_not_emit_or_pair_as_file_events(self):
        folder=r'C:\Docs\old'
        new_folder=r'C:\Other\new'
        file=r'C:\Docs\README'
        events=RenamePairs().consume([(1,folder,0x10),(4,folder,0x10),(5,new_folder,0x10),
                                      (2,new_folder,0x10),(1,file,0x20),(2,file,0x20)],now=1)
        self.assertEqual([(kind, details['path']) for kind,details in events],
                         [('file.created',file),('file.deleted',file)])
