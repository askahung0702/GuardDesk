"""Bounded caller-owned UAC identity probe; never reads edit/value properties.

UI Automation ABI: Microsoft's win32metadata UIAutomationClient.h. This module
is test-only. Run UIA in a disposable subprocess with a hard parent timeout.
"""
import ctypes
from ctypes import wintypes as w
import uuid

P=ctypes.c_void_p

class Value(ctypes.Union):
    _fields_=[('integer',ctypes.c_long),('boolean',ctypes.c_short),('pointer',P),('record',P*2)]

class Variant(ctypes.Structure):
    _anonymous_=('value',)
    _fields_=[('vt',ctypes.c_ushort),('reserved',ctypes.c_ushort*3),('value',Value)]

def invoke(obj,index,*signature):
    table=ctypes.cast(obj,ctypes.POINTER(ctypes.POINTER(P))).contents
    return ctypes.WINFUNCTYPE(ctypes.c_long,P,*signature)(table[index])

def checked(code):
    if code<0:raise OSError('UIA failed: '+hex(code&0xffffffff))

def exact_label(hwnd,label,expected_pid,diagnostics=None):
    """Search only the supplied window for an exact synthetic filename label.

    No root enumeration, ValuePattern, password fields, captions or text logs.
    Return a boolean; caller separately verifies foreground/process/session.
    """
    if not isinstance(label,str) or not 1<=len(label)<=160:raise ValueError('Invalid owned label')
    ole=ctypes.WinDLL('ole32');auto=ctypes.WinDLL('oleaut32')
    ole.CoInitializeEx.argtypes=[P,w.DWORD];ole.CoInitializeEx.restype=ctypes.c_long
    ole.CoCreateInstance.argtypes=[P,P,w.DWORD,P,ctypes.POINTER(P)];ole.CoCreateInstance.restype=ctypes.c_long
    auto.SysAllocString.argtypes=[w.LPCWSTR];auto.SysAllocString.restype=P
    auto.VariantClear.argtypes=[ctypes.POINTER(Variant)]
    checked(ole.CoInitializeEx(None,0))
    objects=[];value=Variant();prop=Variant()
    try:
        cls=(ctypes.c_ubyte*16).from_buffer_copy(uuid.UUID('ff48dba4-60ef-4201-aa87-54103eef594e').bytes_le)
        iid=(ctypes.c_ubyte*16).from_buffer_copy(uuid.UUID('30cbe57d-d9d0-452a-ab13-7ac5ac4825ee').bytes_le)
        client=P();checked(ole.CoCreateInstance(ctypes.byref(cls),None,1,ctypes.byref(iid),ctypes.byref(client)));objects.append(client)
        element=P();checked(invoke(client,6,w.HWND,ctypes.POINTER(P))(client,hwnd,ctypes.byref(element)));objects.append(element)
        value.vt=8;value.pointer=auto.SysAllocString(label)
        if not value.pointer:raise MemoryError('UIA label allocation')
        condition=P();checked(invoke(client,23,ctypes.c_int,Variant,ctypes.POINTER(P))(client,30005,value,ctypes.byref(condition)));objects.append(condition)
        found=P();checked(invoke(element,5,ctypes.c_int,P,ctypes.POINTER(P))(element,4,condition,ctypes.byref(found)))
        if diagnostics is not None:diagnostics['found']=bool(found)
        if not found:return False
        objects.append(found)
        # Verify the matched label is a non-password text control in this PID.
        for identifier,wanted in ((30002,expected_pid),(30003,50020),(30019,False)):
            checked(invoke(found,10,ctypes.c_int,ctypes.POINTER(Variant))(found,identifier,ctypes.byref(prop)))
            if diagnostics is not None:diagnostics[str(identifier)]={'vt':prop.vt,'scalar':prop.integer if prop.vt==3 else bool(prop.boolean) if prop.vt==11 else None}
            valid=(prop.vt==11 and bool(prop.boolean)==wanted) if type(wanted) is bool else (prop.vt==3 and prop.integer==wanted)
            auto.VariantClear(ctypes.byref(prop))
            if not valid:return False
        return True
    finally:
        auto.VariantClear(ctypes.byref(prop));auto.VariantClear(ctypes.byref(value))
        for obj in reversed(objects):
            if obj:invoke(obj,2)(obj)
        ole.CoUninitialize()

def guard_proof(proof,*,hwnd,pid,created,session,now):
    """Pure gate rechecked immediately before capture and both Escape edges."""
    return bool(isinstance(proof,dict) and proof.get('matched') is True
        and proof.get('hwnd')==hwnd and proof.get('pid')==pid
        and proof.get('created')==created and proof.get('session')==session
        and type(proof.get('checked_at')) in (int,float)
        and 0<=now-proof['checked_at']<=5)
