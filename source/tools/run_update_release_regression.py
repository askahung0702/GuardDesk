"""Update/deployment regression gate, including prior machine handoff contracts."""
from tools import run_machine_agent_regression as suite
from tools.build_dependencies import verify
verify(suite.ROOT)
suite.NAMES+=['test_bundled_release','test_release_scope','test_update_storage','test_deployment_scope_gate','test_update_progress']
snapshot=suite.snapshot
if __name__=='__main__':raise SystemExit(suite.main())
