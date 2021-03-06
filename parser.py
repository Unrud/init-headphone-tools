#!/usr/bin/env python3

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Copyright 2015-2016 Unrud <unrud@openaliasbox.org>

# Parses log files of I/O port accesses generated by emulator.py and
# prints CMD and Data0

import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("log", metavar="LOG", type=str)
    args = parser.parse_args()

    current_direction = None
    current_control = None
    current_data0 = None
    with open(args.log, "r") as log_file:
        # Header
        log_file.readline()
        print("#    CMD   Data0")
        for line in log_file.readlines():
            line = line.strip()
            if not line:
                continue
            direction, addr, data = line.split(";")
            if direction != "Out":
                continue
            addr = int(addr, 16)
            if addr in (0xCFC, 0xCF8):
                continue
            # Only one byte data
            assert(len(data) in (1,2))
            data = int(data, 16)
            if addr == 0xf044:
                assert((data>>1)==0x73)
                assert(current_direction == None)
                current_direction = "In" if data & 1 else "Out"
            if addr == 0xf043:
                assert(current_control == None)
                current_control = data
            if addr == 0xf045:
                assert(current_data0 == None)
                current_data0 = data
            if addr == 0xf046:
                assert(data == 0)
            if (current_direction != None and current_control != None and
                current_data0 != None):
                if current_direction == "Out":
                    print("    [0x%02x, 0x%02x]," % (current_control, current_data0))
                else:
                    print("#   Read 0x%02x" % current_control)
                current_direction = None
                current_control = None
                current_data0 = None


if __name__ == "__main__":
    main()
