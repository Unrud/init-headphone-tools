#!/usr/bin/env python3

# Emulates the Windows kernel driver on Linux.
# Communicates with the debugger over TCP/IP.
# Can log all I/O port accesses.

import argparse
import logging
import os
import pickle
import socket
import struct
import subprocess
from collections import namedtuple

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 25233

PCI_ENUMERATION_IOCTL = 0x9C402494
IN_BYTE_IOCTL = 0x9C4024D0
OUT_BYTE_IOCTL = 0x9C4024C4

PCI_ENUMERATION_STRUCT = "IIIIII"
PciEnumeration = namedtuple("PciEnumeration", "bus device func pcireg output ignore1")

IN_OUT_STRUCT = "III"
InOut = namedtuple("InOut", "address output input")

PCI_ENABLE_BIT = 0x80000000
PCI_CONFIG_ADDRESS = 0xcf8;
PCI_CONFIG_DATA = 0xcfc

PCI_VENDOR_PATH = "/sys/bus/pci/devices/%04x:%02x:%02x.%x/vendor"
PCI_DEVICE_PATH = "/sys/bus/pci/devices/%04x:%02x:%02x.%x/device"

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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=str)
    parser.add_argument("--host", default=DEFAULT_HOST, type=str)
    parser.add_argument("--port", default=DEFAULT_PORT, type=int)
    args = parser.parse_args()

    if args.log:
        log_file = open(args.log, "w")
        log_file.write("direction;addr;data\n")
        log_file.flush()
    else:
        log_file = None

    port_fd = os.open("/dev/port", os.O_RDWR|os.O_NDELAY)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.host, args.port))
    logging.info("Listening for requests on %s:%d", args.host, args.port)
    s.listen(0)
    while True:
        conn, addr = s.accept()
        logging.debug("Connection from %s:%d", *addr)
        d_len = int(conn.recv(10))
        d = conn.recv(d_len)
        request = pickle.loads(d)
        # request: inBuffer, outBuffer, dwIoControlCode, nInBufferSize, nOutBufferSize

        if request["dwIoControlCode"] == PCI_ENUMERATION_IOCTL:
            pci_enum = PciEnumeration._make(
                struct.unpack(PCI_ENUMERATION_STRUCT, request["inBuffer"]))
            logging.debug("PCI enumeration requested "
                          "(Bus: 0x%x Device: 0x%x Func: 0x%x Reg: 0x%x)",
                          pci_enum.bus, pci_enum.device,
                          pci_enum.func, pci_enum.pcireg)
            setpci_cmd = [
                "setpci", "-s",
                "%02x:%02x.%x" % (pci_enum.bus, pci_enum.device, pci_enum.func),
                "%x.w" % pci_enum.pcireg]
            output = subprocess.run(setpci_cmd, stdout=subprocess.PIPE).stdout
            if output:
                output = int(output, 16)
            else:
                logging.warning("Can't read requested register")
                output = 0xffff
            logging.debug("Enumeration result: 0x%x", output)
            pci_enum = pci_enum._replace(output=output)
            request["outBuffer"] = struct.pack(PCI_ENUMERATION_STRUCT, *pci_enum)
        elif request["dwIoControlCode"] == IN_BYTE_IOCTL:
            in_out = InOut._make(struct.unpack(IN_OUT_STRUCT, request["inBuffer"]))
            logging.debug("Read byte from 0x%x requested", in_out.address)
            os.lseek(port_fd, in_out.address, os.SEEK_SET)
            output = from_little_endian(os.read(port_fd, 1))
            logging.debug("Read 0x%x from 0x%x", output, in_out.address)
            in_out = in_out._replace(output=output)
            request["outBuffer"] = struct.pack(IN_OUT_STRUCT, *in_out)
            if log_file:
                log_file.write("In;%x;%x\n" % (in_out.address, output))
                log_file.flush()
        elif request["dwIoControlCode"] == OUT_BYTE_IOCTL:
            logging.debug("Write byte 0x%x to 0x%x requested",
                          in_out.input, in_out.address)
            in_out = InOut._make(struct.unpack(IN_OUT_STRUCT, request["inBuffer"]))
            os.lseek(port_fd, in_out.address, os.SEEK_SET)
            os.write(port_fd, to_little_endian(in_out.input, 1))
            if log_file:
                log_file.write("Out;%x;%x\n" % (in_out.address, in_out.input))
                log_file.flush()
        else:
            logging.warning("Unknown ioctl 0x%x received", request["dwIoControlCode"])

        logging.debug("InBuffer:  %s", format_hex(request["inBuffer"]))
        logging.debug("OutBuffer: %s", format_hex(request["outBuffer"]))
        d = pickle.dumps(request)
        d_len = len(d)
        conn.send(b"%010d" % d_len)
        conn.send(d)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    main()
