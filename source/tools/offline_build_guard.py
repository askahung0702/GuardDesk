"""Block management-center fixtures before binding, including swallowed attempts."""
from functools import wraps
from unittest.mock import patch

def guarded_main(function):
    @wraps(function)
    def guarded(*args,**kwargs):
        attempts=[]
        def deny(*args,**kwargs):
            attempts.append('TCP_server_constructor_denied')
            raise RuntimeError('Management center start prohibited during offline build')
        with patch('socketserver.TCPServer.__init__',deny):
            try:return function(*args,**kwargs)
            finally:
                if attempts:raise RuntimeError('Offline build attempted to start a management center')
    return guarded
