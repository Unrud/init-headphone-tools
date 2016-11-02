import logging
import os
import pickle
import socket
from ctypes import *

from .defines import *

DEBUG_EVENT_STR = {
    EXCEPTION_DEBUG_EVENT: "EXCEPTION_DEBUG_EVENT",
    CREATE_THREAD_DEBUG_EVENT: "CREATE_THREAD_DEBUG_EVENT",
    CREATE_PROCESS_DEBUG_EVENT: "CREATE_PROCESS_DEBUG_EVENT",
    EXIT_THREAD_DEBUG_EVENT: "EXIT_THREAD_DEBUG_EVENT",
    EXIT_PROCESS_DEBUG_EVENT: "EXIT_PROCESS_DEBUG_EVENT",
    LOAD_DLL_DEBUG_EVENT: "LOAD_DLL_DEBUG_EVENT",
    UNLOAD_DLL_DEBUG_EVENT: "UNLOAD_DLL_DEBUG_EVENT",
    OUTPUT_DEBUG_STRING_EVENT: "OUTPUT_DEBUG_STRING_EVENT",
    RIP_EVENT: "RIP_EVENT",
}

EXCEPTION_STR = {
    EXCEPTION_ACCESS_VIOLATION:  "EXCEPTION_ACCESS_VIOLATION",
    EXCEPTION_BREAKPOINT: "EXCEPTION_BREAKPOINT",
    EXCEPTION_GUARD_PAGE: "EXCEPTION_GUARD_PAGE",
    EXCEPTION_SINGLE_STEP: "EXCEPTION_SINGLE_STEP",
}

kernel32 = windll.kernel32

def format_hex(iterable, prefix="", per_line=0):
    s = ""
    c = 0
    new_line = False
    for v in iterable:
        if c == 0:
            s += prefix
        s += "%02x "%v
        c+=1
        new_line = False
        if per_line > 0 and c==per_line:
            s += "\n"
            c=0
            new_line = True
    return s.rstrip("\n ")

def raise_windows_error():
    raise OSError(GetLastError(), FormatError())

def from_little_endian(data : bytes) -> int:
    n = 0
    for d in reversed(data):
        n <<= 8
        n += d
    return n

def to_little_endian(n : int, length : int) -> bytes:
    data = b""
    for _ in range(length):
        data += bytes((n & 0xFF,))
        n >>= 8
    return data

class Debugger():
    def __init__(self):
        self._h_process = None
        self._pid = None
        self._breakpoints = {}
        self._debugee_initialized = False

    def _open_process(self):
        h_process = kernel32.OpenProcess(
            PROCESS_ALL_ACCESS, # dwDesiredAccess
            False, # bInheritHandle
            self._pid) # dwProcessId
        if h_process:
            self._h_process = h_process
            logging.debug("Process opened")
        else:
            raise_windows_error()

    def load_process(self, command : bytes):
        if self._pid is not None:
            raise ValueError("Already attached to a process")
        creation_flags = DEBUG_PROCESS
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0
        startupinfo.cb = sizeof(startupinfo)
        if kernel32.CreateProcessA(
                None, # lpApplicationName
                command, # lpCommandLine
                None, # lpProcessAttributes
                None, # lpThreadAttributes
                False, # bInheritHandles
                creation_flags, # dwCreationFlags
                None, # lpEnvironment
                None, # lpCurrentDirectory
                byref(startupinfo), # lpStartupInfo
                byref(process_information)): # lpProcessInformation
            self._pid = process_information.dwProcessId;
            logging.debug("Process loaded: %d", self._pid)
            self._open_process()
        else:
            raise_windows_error()

    def attach_process(self, pid : int):
        if self._pid is not None:
            raise ValueError("Already attached to a process")
        self._pid = pid
        self._open_process()
        if kernel32.DebugActiveProcess(
                self._pid): # dwProcessId
            logging.debug("Debugger attached")
        else:
            raise_windows_error()

    def detach_process(self):
        if self._pid is None:
            raise ValueError("Not attached to a process")
        if kernel32.DebugActiveProcessStop(self._pid):
            logging.debug("Debugger detached")
        else:
            raise_windows_error()
        self._pid = None
        self._h_process = None
        self._breakpoints.clear()
        self._debugee_initialized = False

    def run(self):
        if self._pid is None:
            raise ValueError("Not attached to a process")
        debug_event = DEBUG_EVENT()
        while True:
            if not kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
                raise_windows_error()
            thread_id = debug_event.dwThreadId;
            event_code = debug_event.dwDebugEventCode
            logging.debug("Event %s from thread %d",
                          DEBUG_EVENT_STR.get(event_code, str(event_code)),
                          thread_id)

            if event_code == EXCEPTION_DEBUG_EVENT:
                exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                logging.debug("Exception %s at 0x%x from thread %d",
                        EXCEPTION_STR.get(exception, str(exception)),
                        exception_address, thread_id)
                if exception == EXCEPTION_BREAKPOINT and not self._debugee_initialized:
                    self._debugee_initialized = True
                    self.on_process_initialized()
                else:
                    if exception_address in self._breakpoints:
                        self.unset_breakpoint(exception_address)
                        context = self.get_thread_context(thread_id)
                        context.Eip -= 1
                        self.set_thread_context(thread_id, context)
                    self.on_exception(thread_id, exception, exception_address)
            elif event_code == EXIT_PROCESS_DEBUG_EVENT:
                return

            if not kernel32.ContinueDebugEvent(
                    debug_event.dwProcessId,
                    debug_event.dwThreadId,
                    DBG_CONTINUE):
                raise_windows_error()

    def virtual_protect(self, address : int, size : int, protection : int) -> int:
        old_protect = c_ulong(0)
        if not kernel32.VirtualProtectEx(self._h_process, address, size,
                                         protection, byref(old_protect)):
            raise_windows_error()
        return old_protect.value

    def write_process_memory(self, address : int , data : bytes):
        logging.debug("Write memory at 0x%x for %d byte(s)", address, len(data))
        old_protect = self.virtual_protect(address, len(data), PAGE_EXECUTE_READWRITE)
        try:
            count = c_ulong(0)
            c_data = c_char_p(data[:])
            if not kernel32.WriteProcessMemory(
                    self._h_process,
                    address,
                    c_data,
                    len(data),
                    byref(count)):
                raise_windows_error()
        finally:
            self.virtual_protect(address, len(data), old_protect)

    def read_process_memory(self, address : int, length : int) -> bytes:
        logging.debug("Read memory at 0x%x for %d byte(s)", address, length)
        read_buf = create_string_buffer(length)
        count = c_ulong(0)
        if kernel32.ReadProcessMemory(
                self._h_process,
                address,
                read_buf,
                length,
                byref(count)):
            return b"" + read_buf.raw
        else:
            raise_windows_error()

    def _open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        if h_thread:
            return h_thread
        else:
            raise_windows_error()

    def _enumerate_threads(self):
        h_snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self._pid)
        if h_snapshot:
            thread_entry = THREADENTRY32()
            thread_list = []
            thread_entry.dwSize = sizeof(thread_entry)
            ret = kernel32.Thread32First(h_snapshot, byref(thread_entry))
            while ret:
                if thread_entry.th32OwnerProcessID == self._pid:
                    thread_list.append(thread_entry.th32ThreadID)
                ret = kernel32.Thread32Next(h_snapshot, byref(thread_entry))
            if kernel32.CloseHandle(h_snapshot):
                return thread_list
        raise_windows_error()

    def get_thread_context(self, thread_id):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        h_thread = self._open_thread(thread_id)
        try:
            if kernel32.GetThreadContext(h_thread, byref(context)):
                return context
            else:
                raise_windows_error()
        finally:
            if not kernel32.CloseHandle(h_thread):
                raise_windows_error()

    def set_thread_context(self, thread_id, context):
        h_thread = self._open_thread(thread_id)
        try:
            if not kernel32.SetThreadContext(h_thread, byref(context)):
                raise_windows_error()
        finally:
            if not kernel32.CloseHandle(h_thread):
                raise_windows_error()

    def set_breakpoint(self, address : int):
        logging.debug("Set breakpoint at 0x%x", address)
        original_byte = self.read_process_memory(address, 1)
        self.write_process_memory(address, b"\xCC") # int3
        self._breakpoints[address] = original_byte

    def unset_breakpoint(self, address : int):
        logging.debug("Unset breakpoint at 0x%x", address)
        if address not in self._breakpoints:
            raise ValueError("No breakpoint at 0x%x", address)
        self.write_process_memory(address, self._breakpoints[address])
        del self._breakpoints[address]

    def on_process_initialized(self):
        pass

    def on_exception(self, thread_id, exception, exception_address):
        pass

    @staticmethod
    def find_function_address(dll : bytes, function : bytes) -> int:
        handle = kernel32.GetModuleHandleA(dll)
        release_handle_func = lambda: True
        if kernel32.GetLastError() == 126: # Unknown error
            logging.debug("Trying to load library: %s", dll)
            handle = kernel32.LoadLibraryA(dll)
            release_handle_func = lambda: kernel32.FreeLibrary(handle)
        if not handle:
            raise_windows_error()
        try:
            address = kernel32.GetProcAddress(handle, function)
            if address:
                return address
            else:
                raise_windows_error()
        finally:
            if not release_handle_func():
                raise_windows_error()
