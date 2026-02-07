#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝ 

import sys
import importlib

 
try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline
    except ImportError:
        readline = None

 
try:
    from lib.config import all_modules
except ImportError:
    print('[!] Failed to load ./config.py')
    sys.exit(1)


class MiniBloodcat:
    def __init__(self):
        self.modules = all_modules
        self.current = None

    def banner(self):
        print(r'''
        _..---...,""-._     ,/}/)
     .''        ,      ``..'(/-<
    /   _      {      )         \
   ;   _ `.     `.   <         a(
 ,'   ( \  )      `.  \ __.._ .: y
(  <\_-) )'-.____...\  `._   //-'
 `. `-' /-._)))      `-._)))
   `...'          
                Blood-Cat CVE Exploit Console
Maptnh@S-H4CK13 | type `help` | https://github.com/MartinxMax/
---------------------------------------------------------------''')

    def help(self):
        print('''
Core Commands
=============

help                Show help
show                Show modules / parameters
use <id>             Select module
set <key> <value>    Set parameter
run                 Execute module
back                Back to module list
exit / quit          Exit console
        ''')

    def show_modules(self):
        print()
        print("Matching Modules")
        print("=" * 78)
        print(f"{'ID':<4} {'Name':<30} Description")
        print("-" * 78)

        for idx, m in enumerate(self.modules, start=1):
            name = f"{m['dev'].lower()}/{m['CVE'].lower()}"
            desc = m.get("descript", "")
            print(f"{idx:<4} {name:<30} {desc}")

        print()

    def show_params(self):
        params = self.current.get('parameter', {})
        print('\nParameter       | Value    | Description')
        print('-' * 70)
        for k, v in params.items():
            val = v.get('var', '')
            desc = v.get('descript', '')
            print(f'{k:<15}| {str(val):<8}| {desc}')
        print()

    def use(self, idx):
        try:
            index = int(idx) - 1
            if index < 0 or index >= len(self.modules):
                raise IndexError
            self.current = self.modules[index]
            print(f'[*] Using module {self.current["CVE"]}')
        except Exception:
            print('[!] Invalid module ID')

    def set_param(self, key, value):
        params = self.current.get('parameter', {})
        if key in params:
            params[key]['var'] = value
            print(f'[*] {key} => {value}')
        else:
            print('[!] Parameter does not exist')

    def run_module(self):
        module_path = self.current.get('module')
        params = self.current.get('parameter', {})

        try:
            mod = importlib.import_module(module_path)
            exploit = mod.Exploit()
            kwargs = {k: v['var'] for k, v in params.items()}
            exploit.run(**kwargs)
        except Exception as e:
            print(f'[!] Run failed: {e}')

    def repl(self):
        while True:
            try:
                prompt = 'Bloodcat@exp# ' if not self.current else f'Bloodcat@({self.current["CVE"]})# '
                cmd = input(prompt).strip()
            except (KeyboardInterrupt, EOFError):
                print('\nexit')
                break

            if not cmd:
                continue

            args = cmd.split()

            if args[0] in ('exit', 'quit'):
                break

            elif args[0] == 'help':
                self.help()

            elif args[0] == 'show':
                if self.current is None:
                    self.show_modules()
                else:
                    self.show_params()

            elif args[0] == 'use' and len(args) == 2:
                self.use(args[1])

            elif args[0] == 'set' and len(args) >= 3:
                if not self.current:
                    print('[!] No module selected')
                    continue
                self.set_param(args[1], ' '.join(args[2:]))

            elif args[0] == 'run':
                if not self.current:
                    print('[!] No module selected')
                    continue
                self.run_module()

            elif args[0] == 'back':
                self.current = None

            else:
                print('[!] Unknown command, type help')


if __name__ == '__main__':
    console = MiniBloodcat()
    console.banner()
    console.repl()
