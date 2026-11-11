"""Reversible fixed browser policies. Registry readback is not browser acceptance."""
import copy
import json
import os
from contextlib import contextmanager
from pathlib import Path
from .category_rules import website,WEBSITE_DEFAULT
from .serialization import canonical,digest

ROOTS={'chrome':r'Software\Policies\Google\Chrome','edge':r'Software\Policies\Microsoft\Edge'}
LISTS=('URLBlocklist','URLAllowlist')
EMPTY={k:None for k in LISTS}


class Registry:
    def read_value(self,browser,name,slot):
        import winreg as w
        try:
            with w.OpenKey(w.HKEY_LOCAL_MACHINE,ROOTS[browser]+'\\'+name,0,w.KEY_QUERY_VALUE|w.KEY_WOW64_64KEY) as key:data,typ=w.QueryValueEx(key,slot)
        except FileNotFoundError:return None
        if typ!=w.REG_SZ or not isinstance(data,str) or len(data)>2048:raise OSError('Foreign browser policy value preserved')
        return data

    def read(self,browser):
        import winreg as w
        result={}
        for name in LISTS:
            try:key=w.OpenKey(w.HKEY_LOCAL_MACHINE,ROOTS[browser]+'\\'+name,0,w.KEY_READ|w.KEY_WOW64_64KEY)
            except FileNotFoundError:result[name]=None;continue
            with key:
                count=w.QueryInfoKey(key)[1]
                if count>1000:raise OSError('Browser policy exceeds supported bound')
                values={}
                for index in range(count):
                    slot,data,typ=w.EnumValue(key,index)
                    if typ!=w.REG_SZ or not isinstance(data,str) or len(data)>2048:raise OSError('Foreign browser policy type preserved')
                    values[slot]=data
                result[name]=values
        return result

    def value(self,browser,name,slot,value):
        import winreg as w
        path=ROOTS[browser]+'\\'+name
        if value is None:
            try:key=w.OpenKey(w.HKEY_LOCAL_MACHINE,path,0,w.KEY_SET_VALUE|w.KEY_WOW64_64KEY)
            except FileNotFoundError:return
            with key:
                try:w.DeleteValue(key,slot)
                except FileNotFoundError:pass
        else:
            with w.CreateKeyEx(w.HKEY_LOCAL_MACHINE,path,0,w.KEY_SET_VALUE|w.KEY_WOW64_64KEY) as key:w.SetValueEx(key,slot,0,w.REG_SZ,value)

    def prune(self,browser,name):
        import winreg as w
        try:
            with w.OpenKey(w.HKEY_LOCAL_MACHINE,ROOTS[browser]+'\\'+name,0,w.KEY_READ|w.KEY_WOW64_64KEY) as key:
                subkeys,values,_=w.QueryInfoKey(key)
            if subkeys or values:raise OSError('Foreign browser policy entries preserved')
            w.DeleteKeyEx(w.HKEY_LOCAL_MACHINE,ROOTS[browser]+'\\'+name,w.KEY_WOW64_64KEY)
        except FileNotFoundError:pass


def snapshot(value):
    if not isinstance(value,dict) or set(value)!=set(LISTS):raise OSError('Invalid browser ownership snapshot')
    from .category_rules import filter_text
    for items in value.values():
        if items is None:continue
        if not isinstance(items,dict) or len(items)>1000:raise OSError('Invalid browser ownership entries')
        for key,val in items.items():
            if not isinstance(key,str) or not key.isascii() or not key.isdigit() or not 1<=int(key)<=1000 or str(int(key))!=key or filter_text(val)!=val:raise OSError('Invalid owned browser rule')
    return value


class WebsiteController:
    def __init__(self,directory,registry=None):
        self.directory=Path(directory);self.registry=registry if registry is not None else Registry()

    def guard(self,path=None):
        if isinstance(self.registry,Registry):
            from .update_native import protected_tree
            protected_tree(self.directory,recursive=False)
            if path and path.exists():protected_tree(path,recursive=False)
        if path and path.is_symlink():raise OSError('Ownership journal cannot be a link')

    def save(self,path,state):
        self.guard(path);tmp=path.with_suffix('.new');self.guard(tmp)
        with tmp.open('w',encoding='utf-8') as f:
            f.write(canonical(state));f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)

    def load(self,path):
        self.guard(path)
        if not path.exists():return None
        if path.stat().st_size>1200000:raise OSError('Ownership journal too large')
        state=json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(state,dict) or set(state)!={'format','previous','target','pending'} or type(state['format']) is not int or state['format']!=1 or type(state['pending']) is not bool:raise OSError('Invalid ownership journal')
        snapshot(state['previous']);snapshot(state['target'])
        return state

    def transition(self,browser,before,after):
        current=self.registry.read(browser)
        # Validate the entire observed transition before the first write.
        for name in LISTS:
            old=before[name] or {};new=after[name] or {};now=current[name] or {}
            if set(now)-set(old)-set(new):raise OSError('External browser policy change preserved')
            if any(now.get(slot) not in (old.get(slot),new.get(slot)) for slot in set(now)|set(old)|set(new)):raise OSError('External browser policy value preserved')
        for name in LISTS:
            old=before[name] or {};new=after[name] or {}
            for slot in sorted(set(old)|set(new),key=int):
                # Repeat conflict check immediately before mutation.
                # O(n), not n complete registry enumerations for n rules.
                # Additional foreign slots are checked by the final snapshot;
                # each slot we mutate is rechecked immediately before writing.
                observed=self.registry.read_value(browser,name,slot) if hasattr(self.registry,'read_value') else (self.registry.read(browser)[name] or {}).get(slot)
                if observed not in (old.get(slot),new.get(slot)):raise OSError('External browser policy change preserved')
                if observed!=new.get(slot):self.registry.value(browser,name,slot,new.get(slot))
            if after[name] is None:self.registry.prune(browser,name)
        if self.registry.read(browser)!=after:raise OSError('Browser policy readback mismatch')

    @contextmanager
    def exclusive(self):
        import msvcrt
        lock=self.directory/'website-policy.lock';self.guard(lock)
        with lock.open('a+b') as stream:
            if not stream.seek(0,2):stream.write(b'0');stream.flush()
            stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
            try:yield
            finally:
                stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)

    def apply(self,control):
        website(control);self.guard()
        with self.exclusive():return self._apply(control)

    def _apply(self,control):
        website(control);self.guard();result={}
        for browser in ROOTS:
            path=self.directory/('website-policy-'+browser+'.json')
            try:
                state=self.load(path)
                active=control['enabled'] and browser in control['browsers']
                desired={name:({str(i+1):r for i,r in enumerate(control[key])} or None) if active else None for name,key in zip(LISTS,('blocked','allowed'))}
                if state and state['pending']:
                    self.transition(browser,state['previous'],state['target'])
                    state['pending']=False;self.save(path,state)
                current=self.registry.read(browser)
                if state:
                    if current!=state['target']:raise OSError('External policy drift preserved; MIS review required')
                elif current!=EMPTY:
                    if active and desired!=EMPTY:raise OSError('Existing company browser policy preserved')
                    result[browser]={'state':'unmanaged_preserved'};continue
                if current!=desired:
                    state={'format':1,'previous':current,'target':desired,'pending':True}
                    self.save(path,state)
                    try:self.transition(browser,current,desired)
                    except OSError:
                        # If rollback encounters an external change, keep the
                        # pending journal for diagnosis rather than overwriting.
                        self.transition(browser,desired,current)
                        state={'format':1,'previous':current,'target':current,'pending':False}
                        self.save(path,state)
                        raise
                    state['pending']=False;self.save(path,state)
                if desired==EMPTY:
                    if path.exists():path.unlink()
                    result[browser]={'state':'restored' if state else 'disabled'}
                else:result[browser]={'state':'registry_verified','rules':sum(len(v or {}) for v in desired.values()),'fingerprint':digest(canonical(desired)),'browser_verified':False,'navigation_verified':False,'policy_source':'platform_registry_browser_precedence_not_verified'}
            except (OSError,ValueError) as exc:
                result[browser]={'state':'conflict_or_failed','reason':str(exc)[:180],'browser_verified':False}
        return {'protocol':1,'fingerprint':digest(canonical(control)),'browsers':result,'state':'partial_or_failed' if any(v['state']=='conflict_or_failed' for v in result.values()) else 'reported_requires_browser_test'}

    def restore(self):return self.apply(copy.deepcopy(WEBSITE_DEFAULT))


def sync(agent,control):
    from .custom_windows import trusted_native
    root=trusted_native(agent.config)
    if agent.config_path.resolve()!=root/'config.json':raise OSError('Protected native configuration required')
    return WebsiteController(root).apply(control)
