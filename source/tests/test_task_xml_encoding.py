import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from guarddesk import decommission,update_native


class TaskXmlEncodingTest(unittest.TestCase):
    executable=r'C:\Program Files\GuardDeskPilot\USBControl\GuardDesk.exe'
    config=r'C:\ProgramData\GuardDeskPilot\USBControl\ee5138c901b7ad6898b27c94\config.json'

    def xml(self):
        return ('<?xml version="1.0" encoding="UTF-16"?>\r\r\n'
                '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                '<RegistrationInfo><Description>端點更新測試</Description></RegistrationInfo>'
                '<Actions><Exec><Command>'+self.executable+'</Command>'
                '<Arguments>usb-worker --extended --config "'+self.config+'"</Arguments>'
                '</Exec></Actions></Task>')

    def test_real_xml_encodings_and_unicode_remain_supported(self):
        for document in (self.xml(),self.xml().encode('utf-16'),self.xml().replace('UTF-16','UTF-8').encode('utf-8')):
            decommission.validate_task(document,self.executable,self.config)

    def test_schtasks_mismatched_declaration_uses_strict_oem_decoding(self):
        raw=self.xml().encode('cp950')
        with patch('guarddesk.decommission._task_output_encoding',return_value='cp950'):
            root=decommission.parse_task_xml(raw)
            self.assertEqual(root[0][0].text,'端點更新測試')
            decommission.validate_task(raw,self.executable,self.config)

    def test_oem_fallback_does_not_relax_identity_or_allow_extra_actions(self):
        with patch('guarddesk.decommission._task_output_encoding',return_value='cp950'):
            for document in (self.xml().replace('usb-worker','other'),self.xml().replace('GuardDesk.exe','other.exe'),
                             self.xml().replace(self.config,self.config+'.other'),
                             self.xml().replace('</Actions>','<ComHandler/></Actions>')):
                with self.assertRaises(OSError):
                    decommission.validate_task(document.encode('cp950'),self.executable,self.config)

    def test_malformed_oversized_and_undecodable_output_fail_closed(self):
        with patch('guarddesk.decommission._task_output_encoding',return_value='cp950'):
            for document in (b'not xml',b'x'*65537,self.xml().encode('cp950')+b'\x81',
                             self.xml().encode('cp950')+b'\x00',self.xml().replace('</Task>','').encode('cp950')):
                with self.assertRaises(OSError):decommission.parse_task_xml(document)

    def test_updater_removal_also_normalizes_before_identity_validation(self):
        did='ee5138c901b7ad6898b27c94'
        program=Path(r'C:\Program Files\GuardDeskPilot')
        exe=str(program/'Updater/GuardDesk.exe')
        document=self.xml().replace(self.executable,exe).replace('usb-worker --extended','update-service')
        agent=SimpleNamespace(config={'device_id':did,'update_key':'present'},config_path=Path(self.config))
        with patch('guarddesk.decommission._task_output_encoding',return_value='cp950'), \
             patch('guarddesk.update_native.task_xml',return_value=document.encode('cp950')), \
             patch('guarddesk.update_native.folder',return_value=program), \
             patch('guarddesk.update_native.task_command') as command:
            update_native.remove_broker_task(agent)
            self.assertEqual([call.args[1] for call in command.call_args_list],['/End','/Delete'])


if __name__=='__main__':unittest.main()
