import argparse
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "debugger"))
from debugger import *

# Starts COMMAND and hooks the DeviceIoControl function
# If IP is set the calls gets intercepted and forwarded to an Debugger.
# Can write a log file with the arguemtns of DeviceIoControl calls.

# The Python interpreter that is used to call the DLL.
# It must be 32-bit. If Python 3 doesn't work, try Python 2.
CHILD_PYTHON = sys.executable.encode("ascii")
#CHILD_PYTHON = b"C:\\python27\\python.exe"

DEFAULT_HOST = ""
DEFAULT_PORT = 25233

class HeadphoneDebugger(Debugger):
    def __init__(self, log_file=None, host=None, port=0):
        super().__init__()
        self._create_file_address = self.find_function_address(
            b"kernel32.dll", b"CreateFileA")
        self._device_io_control_address = self.find_function_address(
            b"kernel32.dll", b"DeviceIoControl")
        self._log_file = log_file
        if self._log_file:
            log_file.write("Caller;hDevice;dwIoControlCode;lpInBuffer;nInBufferSize;"
                           "lpOutBuffer;nOutBufferSize;lpBytesReturned;lpOverlapped;"
                           "inBuffer;bytesReturned;outBuffer;\n")
            log_file.flush()
        self._host = host
        self._port = port
        self._device_io_control_return_address = None
        self._last_device_io_control_lpBytesReturned = None
        self._last_device_io_control_lpOutBuffer = None
        self._last_device_io_control_nOutBufferSize = None
        self._create_file_return_address = None

    def detach_process(self):
        super().detach_process()
        self._device_io_control_return_address = None
        self._create_file_return_address = None

    def on_process_initialized(self):
        self.set_breakpoint(self._create_file_address)
        self.set_breakpoint(self._device_io_control_address)

    def on_exception(self, thread_id, exception, exception_address):
        if exception != EXCEPTION_BREAKPOINT:
            return

        if exception_address == self._create_file_address:
            logging.info("CreateFileA intercepted")
            context = self.get_thread_context(thread_id)
            lpFileName = from_little_endian(self.read_process_memory(
                context.Esp + 4, sizeof(c_void_p)))
            # Read string from process memory
            file_name = b""
            i = 0
            while True:
                c = self.read_process_memory(lpFileName + i, 1)
                if not c[0]:
                    break
                file_name += c
                i += 1
            logging.debug("Filename: %s", file_name)
            # Set a breakpoint on the return address
            self._create_file_return_address = from_little_endian(
                self.read_process_memory(context.Esp, 4))
            self.set_breakpoint(self._create_file_return_address)
        elif exception_address == self._create_file_return_address:
            logging.info("Return from CreateFileA intercepted")
            self._create_file_return_address = None
            self.set_breakpoint(self._create_file_address)
        elif exception_address == self._device_io_control_address:
            logging.info("DeviceIoControl intercepted")
            context = self.get_thread_context(thread_id)
            base = context.Esp + 4
            hDevice = from_little_endian(self.read_process_memory(
                base, 4))
            dwIoControlCode = from_little_endian(self.read_process_memory(
                base + 4, 4))
            lpInBuffer = from_little_endian(self.read_process_memory(
                base + 8, 4))
            nInBufferSize = from_little_endian(self.read_process_memory(
                base + 12, 4))
            lpOutBuffer = from_little_endian(self.read_process_memory(
                base + 16, 4))
            nOutBufferSize = from_little_endian(self.read_process_memory(
                base + 20, 4))
            lpBytesReturned = from_little_endian(self.read_process_memory(
                base + 24, 4))
            lpOverlapped = from_little_endian(self.read_process_memory(
                base + 28, 4))
            logging.debug("hDevice: 0x%x", hDevice)
            logging.debug("dwIoControlCode: 0x%x", dwIoControlCode)
            logging.debug("lpInBuffer: 0x%x", lpInBuffer)
            logging.debug("nInBufferSize: 0x%x", nInBufferSize)
            logging.debug("lpOutBuffer: 0x%x", lpOutBuffer)
            logging.debug("nOutBufferSize: 0x%x", nOutBufferSize)
            logging.debug("lpBytesReturned: 0x%x", lpBytesReturned)
            logging.debug("lpOverlapped: 0x%x", lpOverlapped)
            read_buffer = self.read_process_memory(lpInBuffer, nInBufferSize)
            logging.debug("inBuffer:  %s", format_hex(read_buffer))
            write_buffer = self.read_process_memory(lpOutBuffer, nOutBufferSize)
            if self._log_file:
                logging.debug("Writing input to log file")
                self._log_file.write("%x;%x;%x;%x;%x;%x;%x;%x;%x;%s" % (
                    thread_id, hDevice, dwIoControlCode, lpInBuffer, nInBufferSize,
                    lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped,
                    format_hex(read_buffer)))

            # Set a breakpoint on the return address
            self._device_io_control_return_address = from_little_endian(
                self.read_process_memory(context.Esp, 4))
            self.set_breakpoint(self._device_io_control_return_address)
            self._last_device_io_control_lpBytesReturned = lpBytesReturned
            self._last_device_io_control_lpOutBuffer = lpOutBuffer
            self._last_device_io_control_nOutBufferSize = nOutBufferSize

            if self._host:
                logging.debug("Connecting to %s:%d", self._host, self._port)
                data = {
                    "inBuffer": read_buffer,
                    "outBuffer": write_buffer,
                    "dwIoControlCode": dwIoControlCode,
                    "nInBufferSize": nInBufferSize,
                    "nOutBufferSize": nOutBufferSize,
                }
                d = pickle.dumps(data)
                d_len = len(d)
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.connect((self._host, self._port))
                conn.send(b"%010d" % d_len)
                conn.send(d)
                d_len = int(conn.recv(10))
                d = conn.recv(d_len)
                data = pickle.loads(d)
                self.write_process_memory(lpOutBuffer, data["outBuffer"])
                if lpBytesReturned:
                    self.write_process_memory(lpBytesReturned, to_little_endian(data["nOutBufferSize"], 4))
                # Ret
                context.Eax = 1
                context.Eip = from_little_endian(self.read_process_memory(context.Esp, 4))
                context.Esp += 4 + 32
                self.set_thread_context(thread_id, context)
        elif exception_address == self._device_io_control_return_address:
            logging.info("Return from DeviceIoControl intercepted")
            self._device_io_control_return_address = None
            self.set_breakpoint(self._device_io_control_address)

            lpBytesReturned = self._last_device_io_control_lpBytesReturned
            lpOutBuffer = self._last_device_io_control_lpOutBuffer
            nOutBufferSize = self._last_device_io_control_nOutBufferSize
            if lpBytesReturned:
                bytesReturned = from_little_endian(
                    self.read_process_memory(lpBytesReturned, 4))
            else:
                bytesReturned = 0
            if lpOutBuffer and nOutBufferSize:
                write_buffer = self.read_process_memory(lpOutBuffer, nOutBufferSize)
            else:
                write_buffer = b""
            logging.debug("outBuffer: %s", format_hex(write_buffer))
            logging.debug("bytesReturned: 0x%x", bytesReturned)
            if self._log_file:
                logging.debug("Writing output to log file")
                self._log_file.write(";%x;%s\n" % (bytesReturned,
                                                  format_hex(write_buffer)))
                self._log_file.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dll", metavar="DLL", type=str, help="Example: hp.dll")
    parser.add_argument("function", metavar="FUNCTION", type=str, help="Example: InitHeadphone()")
    parser.add_argument("--log", type=str)
    parser.add_argument("--host", default=DEFAULT_HOST, type=str,
                        help="If empty calls to DeviceIoControl are only recoreded")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int)
    args = parser.parse_args()

    def escape(s):
        return s.replace(b"\\", b"\\\\").replace(b"\"", b"\\\"")
    command = b"\"%s\" -c \"%s\"" % (
        escape(CHILD_PYTHON),
        escape(b"from ctypes import *; WinDLL(\"%s\").%s" % (
            escape(args.dll.encode("ascii")), args.function.encode("ascii")
        ))
    )

    if args.log:
        log_file = open(args.log, "w")
    else:
        log_file = None
    debugger = HeadphoneDebugger(log_file, args.host, args.port)
    debugger.load_process(command)
    debugger.run()
    debugger.detach_process()

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    main()
