"""Dedicated, windowed single-file MIS entry point, independent of filename."""
if __name__=='__main__':
    try:
        from guarddesk.mis_onefile import run
        run()
    except (OSError,ValueError) as exc:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None,str(exc),'GuardDesk MIS 遠端協助',0x10)
