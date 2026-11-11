"""New Agent startup can add the MIS entry after an unchanged old updater."""
import json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from guarddesk.mis_support import ensure_agent_launcher

class AgentMISLauncherTest(unittest.TestCase):
    def test_owned_install_marker_required_and_config_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);config=root/'runtime/agent/config.json';config.parent.mkdir(parents=True)
            original=b'{"server":"https://company.example","token":"synthetic-not-transmitted"}';config.write_bytes(original)
            app=root/'app/update-owned';(app/'_internal').mkdir(parents=True)
            (app/'_internal/GuardDeskRemote.exe').write_bytes(b'not executed')
            marker=root/'endpoint-install.json';state={'product':'GuardDeskEndpoint','app':str(app)};marker.write_text(json.dumps(state))
            with patch('guarddesk.desktop_agent.client_root',return_value=root),patch.object(sys,'frozen',True,create=True),patch.object(sys,'executable',str(app/'GuardDeskAgent.exe')):
                ensure_agent_launcher(config)
                launcher=root/'Start-MIS-Remote.cmd';text=launcher.read_bytes()
                self.assertIn(b'--workstation --agent-config',text);self.assertNotIn(b'synthetic-not-transmitted',text)
                self.assertEqual(config.read_bytes(),original)
                launcher.unlink();marker.write_text(json.dumps({**state,'app':str(root/'other-app')}))
                ensure_agent_launcher(config);self.assertFalse(launcher.exists())
                marker.write_text(json.dumps(state));ensure_agent_launcher(root/'other/config.json');self.assertFalse(launcher.exists())

if __name__=='__main__':unittest.main()
