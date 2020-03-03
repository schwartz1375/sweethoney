#!/usr/bin/env python3

__author__ = 'Matthew Schwartz (@schwartz1375)'
__version__ = '0.9'

import hashlib
import time
import pprint
import argparse
import sys
from datetime import datetime

try:
    import pefile
except:
    print('Missing pefile Python module, please check if it is installed.') #pip install pefile
    sys.exit(1)

try:
    import magic
except:
    print('Missing magic Python module, please check if it is installed.') #pip install python-magic on mac os brew install libmagic too
    sys.exit(1)

try:
    from termcolor import colored, cprint
except:
    print('Missing termcolor Python module, please check if it is installed.') #pip install termcolor
    sys.exit(1)

try:
    import ssdeep
except:
    print('Missing ssdeep Python module, please check if it is installed.') #python3 -m pip install ssdeep
    sys.exit(1)

# suspicious APIs to alert on 
alerts = ['AdjustTokenPrivileges', 'OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'ReadProcessMemory',
          'CreateProcess', 'WinExec', 'ShellExecute', 'HttpSendRequest', 'InternetReadFile', 'InternetConnect',
          'CreateService', 'StartService']

def Main(filename):
    print("PE check for '%s':" % filename)
    getFileType(filename)
    try:
        pe = pefile.PE(filename)
    except pefile.PEFormatError:
        cprint("***************************************", 'red')
        cprint("Aw Snap, invaild format!", 'red')
        cprint("Manual inspection required!", 'red')
        cprint("***************************************", 'red')
        sys.exit(1)
    ped = pe.dump_dict()
    #pprint.pprint(ped)
    #dump =  pe.dump_info()
    #print(dump)

    cprint("***************************************", 'blue')
    cprint("Compile information:", 'blue')
    cprint("***************************************", 'blue')
    #Compile time
    comp_time = ped['FILE_HEADER']['TimeDateStamp']['Value']
    comp_time = comp_time.split("[")[-1].strip("]")
    time_stamp, timezone = comp_time.rsplit(" ", 1)
    comp_time = datetime.strptime(time_stamp, "%a %b %d %H:%M:%S %Y")
    print("Compiled on {} {}".format(comp_time, timezone.strip()))

    cprint("***************************************", 'blue')
    cprint("Functions declared and referenced:", 'blue')
    cprint("***************************************", 'blue')
    ret = []
    for lib in pe.DIRECTORY_ENTRY_IMPORT:
        print (str(lib.dll, 'utf-8'))
        for imp in lib.imports:
            if imp.name != None:
                print ('\t' + str(imp.name, 'utf-8'))
            if (imp.name != None) and (imp.name != ""):
                for alert in alerts:
                    #print("\t Alert: " + alert)
                    if imp.name.decode('utf-8').startswith(alert):
                        ret.append(imp.name)
    if len(ret) != 0:
        cprint("***************************************", 'red')
        cprint("Suspicious IAT alerts", 'red', attrs=['bold'])
        cprint("***************************************", 'red')
        #print(*ret, sep=', ')
        for x in ret:
            cprint("\t"+x.decode("utf-8"), 'red', attrs=['bold'])

    cprint("***************************************", 'blue')
    cprint("Looking for exported sysmbols...", 'blue')
    cprint("***************************************", 'blue')
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            #print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal
            print("Name: %s, Ordinal number: %i" % (str(exp.name, 'utf-8'), exp.ordinal))
    except:
        cprint("No exported symbols!", 'magenta')

    cprint("***************************************", 'blue')
    cprint("Getting Sections...", 'blue')
    cprint("***************************************", 'blue')
    for section in pe.sections:
        print(section.Name.decode('UTF-8') + '\t' + section.get_hash_md5())

    cprint("***************************************", 'blue')
    cprint("Getting file statics...", 'blue')
    cprint("***************************************", 'blue')
    raw = pe.write()
    entropy = pe.sections[0].entropy_H(raw)
    cprint('Entropy: %f (Min=0.0, Max=8.0)' % entropy, 'magenta')
    if 6.084 <= entropy <= 6.369:
        cprint("The file is most likely a native executable", 'magenta')
    elif 7.199 <= entropy <= 7.267:
        cprint("The file is most likely packed!", 'red')
    elif 7.295 <= entropy <= 7.312:
        cprint("The file is most likely encrypted!", 'red')
    else:
        cprint("The entropy value (%s) falls outside the 99%% confidence intervals, manual inspection required!" % entropy, 'red')

    print('MD5     hash: %s' % hashlib.md5(raw).hexdigest())
    print('SHA-1   hash: %s' % hashlib.sha1(raw).hexdigest())
    print('SHA-256 hash: %s' % hashlib.sha256(raw).hexdigest())
    print('SHA-512 hash: %s' % hashlib.sha512(raw).hexdigest())
    print('Import hash (imphash): %s' % pe.get_imphash())
    print('fuzzy hash (ssdeep): %s' % ssdeep.hash_from_file(filename))
    #print("List all PE headers")
    #pprint.pprint(dir(pe))
    sys.exit()

def getFileType(filename):
    filetype = magic.from_file(filename)
    cprint("***************************************", 'blue')
    cprint("Getting filetype...", 'blue')
    cprint("***************************************", 'blue')
    cprint(filetype, 'green')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A rapid file analysis tool')
    parser.add_argument("filename", help="The file to be inspected by the tool")
    args = parser.parse_args()
    Main(args.filename)