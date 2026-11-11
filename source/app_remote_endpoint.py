"""Dedicated remote endpoint artifact; no viewer/server dispatch."""
if __name__=='__main__':
    try:
        from guarddesk.remote_endpoint_entry import main
        main()
    except (ValueError,PermissionError,ConnectionError,OSError) as error:
        raise SystemExit(str(error))
