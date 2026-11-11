"""Leased IPv6 preference with exact original-value recovery and conflict checks."""
import json
import time
from .update_client import save
from .update_packages import plain

KEY=r'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
NAME='DisabledComponents'
VALUES={'prefer_ipv4':0x20,'disable':0xff}

class Registry:
    def policy_managed(self):
        import winreg as r
        for path in (r'SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition',r'SOFTWARE\Policies\Microsoft\Windows\TCPIP\Parameters'):
            try:
                with r.OpenKey(r.HKEY_LOCAL_MACHINE,path,0,r.KEY_READ|r.KEY_WOW64_64KEY) as key:
                    subkeys,values,_=r.QueryInfoKey(key)
                    if subkeys or values:return True
            except FileNotFoundError:pass
        return False
    def read(self):
        import winreg as r
        try:
            with r.OpenKey(r.HKEY_LOCAL_MACHINE,KEY,0,r.KEY_READ|r.KEY_WOW64_64KEY) as key:value,kind=r.QueryValueEx(key,NAME)
        except FileNotFoundError:return None
        if kind!=r.REG_DWORD:raise OSError('IPv6 setting has an unexpected registry type')
        return value

    def write(self,value):
        import winreg as r
        with r.CreateKeyEx(r.HKEY_LOCAL_MACHINE,KEY,0,r.KEY_SET_VALUE|r.KEY_WOW64_64KEY) as key:
            if value is None:
                try:r.DeleteValue(key,NAME)
                except FileNotFoundError:pass
            else:r.SetValueEx(key,NAME,0,r.REG_DWORD,value)

class NetworkLease:
    def __init__(self,path,registry=None,clock=time.time):
        self.path=plain(path);self.registry=registry or Registry();self.clock=clock

    def state(self):
        if not self.path.exists():return None
        plain(self.path)
        if isinstance(self.registry,Registry):
            from .update_native import protected_tree
            protected_tree(self.path)
        if self.path.stat().st_size>4096:raise OSError('Network recovery state exceeds bound')
        state=json.loads(self.path.read_text(encoding='utf-8'))
        if (not isinstance(state,dict) or set(state)!={'original','last','previous','expires','managed'} or
                type(state['managed']) is not bool or
                any(v is not None and (type(v) is not int or not 0<=v<=0xffffffff) for v in (state['original'],state['last'],state['previous'])) or
                type(state['expires']) not in (int,float) or not 0<=state['expires']<253402300800):raise OSError('Invalid network recovery state')
        if state['managed'] and state['last'] not in VALUES.values():raise OSError('Invalid managed network setting')
        return state

    def apply(self,mode,online=True):
        if mode not in ('unchanged',*VALUES):raise ValueError('Unsupported network mode')
        state=self.state();current=self.registry.read();now=self.clock()
        if state and state['managed'] and current not in (state['last'],state['previous'],state['original']):
            return {'state':'conflict','reason':'external_registry_change_preserved'}
        if state and state['managed'] and (mode=='unchanged' or now>=state['expires']):
            self.registry.write(state['original'])
            if self.registry.read()!=state['original']:raise OSError('Network recovery readback mismatch')
            state.update(last=state['original'],managed=False,expires=0);save(self.path,state)
            if mode=='unchanged' or not online:return {'state':'restored_requires_restart'}
        if not online:
            if state and state['managed']:return {'state':'configured_requires_restart','mode':next(k for k,v in VALUES.items() if v==state['last']),'recovery_lease_seconds':300}
            return {'state':'restored_requires_restart' if state else 'unchanged'}
        if mode=='unchanged':return {'state':'restored_requires_restart' if state else 'unchanged'}
        if isinstance(self.registry,Registry) and self.registry.policy_managed():return {'state':'conflict','reason':'company_tcpip_policy_present'}
        target=VALUES[mode]
        if not state or not state['managed']:
            state={'original':self.registry.read(),'last':target,'previous':self.registry.read(),'expires':now+300,'managed':True}
        else:state.update(previous=current,last=target,expires=now+300)
        # Persist exact rollback before mutation; original is never inferred.
        save(self.path,state)
        if self.registry.read()!=target:self.registry.write(target)
        if self.registry.read()!=target:raise OSError('Network setting readback mismatch')
        return {'state':'configured_requires_restart','mode':mode,'recovery_lease_seconds':300}

    def restore(self):return self.apply('unchanged',online=False)
