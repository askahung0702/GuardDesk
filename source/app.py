"""Frozen Windows executable entry point."""
import sys

if __name__ == '__main__':
    try:
        from pathlib import Path
        if Path(sys.executable).stem.casefold()=='guarddeskremote':
            from guarddesk.remote_viewer import run
            run(sys.argv[1:])
        elif len(sys.argv)>1 and sys.argv[1]=='document-session-context':
            from guarddesk.remote_trial import reject
            reject('Document session metadata')
            # Small metadata helper does not initialize Agent, Store, HTTP,
            # crypto, collectors, enrollment or user configuration.
            import argparse
            from guarddesk.document_context import run_helper
            parser=argparse.ArgumentParser(description='GuardDesk document session metadata')
            parser.add_argument('--pipe',required=True);parser.add_argument('--parent',required=True,type=int)
            args=parser.parse_args(sys.argv[2:]);run_helper(args.pipe,args.parent)
        elif len(sys.argv)>1 and sys.argv[1].startswith('chrome-extension://'):
            from guarddesk.remote_trial import reject
            reject('Browser native messaging')
            from guarddesk.browser_host import run_host
            run_host()
        else:
            from guarddesk.__main__ import main
            main()
    except (ValueError, PermissionError, ConnectionError, OSError) as exc:
        raise SystemExit(str(exc))
