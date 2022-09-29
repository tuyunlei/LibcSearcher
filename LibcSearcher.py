#!/usr/bin/env python

from __future__ import print_function
import os
import re
import sys


class LibcSearcher(object):
    def __init__(self, *args):
        self.conditions = {}
        for func, address in args:
            self.add_condition(func, address)
        self.libc_database_path = os.path.join(
            os.path.realpath(os.path.dirname(__file__)),
            "libc-database/db/"
        )
        self.database = None
        self.base_addr = None

    def add_condition(self, func, address):
        if not isinstance(func, str):
            print("The function should be a string")
            sys.exit()
        if not isinstance(address, int):
            print("The address should be an int number")
            sys.exit()
        self.conditions[func] = address

    #Wrapper for libc-database's find shell script.
    def decided(self):
        if not self.conditions:
            print("No leaked info provided.")
            print("Please supply more info using add_condition(leaked_func, leaked_address).")
            sys.exit(0)

        results = []
        # only read "*.symbols" file to find
        for fname in os.listdir(self.libc_database_path):
            if not fname.endswith('.symbols'):
                continue
            fpath = os.path.join(self.libc_database_path, fname)
            # print('calcing', fpath)
            delta = self._calc_base(fpath)
            if delta is not None:
                self.base_addr = delta
                results.append(fname)

        if not results:
            print("No matched libc, please add more libc or try others")
            sys.exit(0)

        if len(results) == 1:
            result = results[0]
        else:
            print("Multi Results:")
            for i, result in enumerate(results):
                print(f"{i+1:2d}: {self.pmore(result)}")
            print("Please supply more info using \n\tadd_condition(leaked_func, leaked_address).")
            result = results[self._get_input() - 1]
        print(f"[+] {self.pmore(result)} be choosed.")
        fpath = os.path.join(self.libc_database_path, result)
        with open(fpath, encoding='utf-8', errors='ignore') as f:
            database = {}
            for line in f:
                name, addr = line.split()
                database[name] = int(addr, base=16)
            self.database = database

    def pmore(self, result):
        result = result[:-8]  # .strip(".symbols")
        fpath = os.path.join(self.libc_database_path, result + '.info')
        with open(fpath, encoding='utf-8', errors='ignore') as f:
            info = f.read().strip()
            return f"{info} (id {result})"

    #Wrapper for libc-database's dump shell script.
    def dump(self, func=None):
        if not self.database:
            self.decided()
        if not func:
            results = {}
            funcs = ["__libc_start_main_ret", "system", "dup2", "read", "write", "str_bin_sh"]

            for name in funcs:
                if name in self.database:
                    addr = self.database[name] + self.base_addr
                    # print(name, hex(addr))
                    results[name] = addr
            return results

        if func in self.database:
            return self.database[func] + self.base_addr

        print("No matched, Make sure you supply a valid function name or just add more libc.")
        return 0

    def _calc_base(self, fpath):
        with open(fpath, encoding='utf-8', errors='ignore') as f:
            base = None
            for line in f:
                name, addr = line.split()
                addr = int(addr, base=16)
                if name in self.conditions:
                    condition = self.conditions[name]
                    if condition & 0xfff != addr & 0xfff:
                        return None
                    if base is None:
                        base = condition - addr
                    elif base != condition - addr:
                        return None
            return base

    def _get_input(self):
        while True:
            cmd = input("You can choose it by hand\nOr type 'exit' to quit: ")
            if cmd in ('exit', 'quit'):
                sys.exit(0)
            try:
                return int(cmd)
            except ValueError:
                pass


if __name__ == "__main__":
    obj = LibcSearcher(('puts', 0x00007f19e6e3a970), ('alarm', 0x00007f19e6e9e4f0))
    # print(obj.dump())
    print(hex(obj.dump('puts')))
    # print("[+]system  offset: ", hex(obj.dump("system")))
    # print("[+]/bin/sh offset: ", hex(obj.dump("str_bin_sh")))
