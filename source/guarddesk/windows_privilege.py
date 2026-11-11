"""Privilege query only; no policy adapters or mutation."""
import ctypes
import os

def is_admin():
    return os.name=='nt' and bool(ctypes.windll.shell32.IsUserAnAdmin())
