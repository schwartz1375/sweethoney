#!/usr/bin/env python3

__author__ = 'Matthew Schwartz (@schwartz1375)'
__version__ = '0.8'

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
    cprint("Funcations declared and referenced:", 'blue')
    cprint("***************************************", 'blue')
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print (str(entry.dll, 'utf-8'))
    for function in entry.imports:
       print ("\t" + str(function.name , 'utf-8'))

    cprint("***************************************", 'blue')
    cprint("Looking for exported sysmbols...", 'blue')
    cprint("***************************************", 'blue')
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            #print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal
            print("Name: %s, Ordinal number: %i" % (str(exp.name, 'utf-8'), exp.ordinal))
    except:
        cprint("No exported symbols!", 'red')

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
    sys.exit()
    #print("List all PE headers")
    #pprint.pprint(dir(pe))

def getFileType(filename):
    filetype = magic.from_file(filename)
    cprint("***************************************", 'blue')
    cprint("Geting filetype...", 'blue')
    cprint("***************************************", 'blue')
    cprint(filetype, 'magenta')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A rapid file analysis tool')
    parser.add_argument("filename", help="The file to be inspected by the tool")
    args = parser.parse_args()
    Main(args.filename)