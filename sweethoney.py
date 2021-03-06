#!/usr/bin/env python3

__author__ = 'Matthew Schwartz (@schwartz1375) & Santry (@san4n6)' 
__version__ = '1.1.2' 

import hashlib
import time
import argparse
import sys
import string
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

#registry alerts 
regalerts = ['RegCreateKeyExA',' RegDeleteValueA', 'RegFlushKey', 'RegSetValueExA','RtlCreateRegistryKey','RtlWriteRegistryValue',]

#network alerts 
netalerts = ['InternetCloseHandle','InternetOpenHandle','InternetOpenA','InternetOpenURLA','InternetReadFile','FtpPutFile',
			 'Accept','Bind','HttpSendRequest','InternetConnect','URLDownloadToFile']

#process alerts 
psalerts = ['CreateProcess','EnumProcesses','CreateRemoteThread','CreateService','ControlService','StartService','ReadProcessMemory',
		   'WriteProcessMemory','OpenProcess','VirtualAllocEx','WriteProcessMemory','GetModuleHandle','GetProcAddress','LoadLibraryA',
		   'LoadLibrary']

#malicious general funcitons
sysalerts = ['AdjustTokenPrivileges','WinExec', 'ShellExecute','FindFirstFile','FindNextFile','Gethostbyname','Gethostname',
			 'CreateMutex','GetAsyncKeyStat','Fopen','GetEIP','malloc','GetTempPathA','ShellExecuteA','IsWoW64Process','LdrLoadDll',
			 'MapViewOfFile','NetScheduleJobAdd']

#dropper alerts
dropalerts = ['FindResource','LoadResource','SizeOfResource','LockResource','NtResumeThread','NtMapViewOfSection','NtCreateSection']

#dll injection alerts
dlinjalerts = ['LoadLibraryA','GetProcAddress','GetWindowsThreadProcessId','SetWindowsHookEx','BroadcastSystemMessage','OpenProcess',
			   'OpenProcess','WriteProcessMemory','CreateRemoteThread']

#anti vm/debugging alerts
antialerts = ['GetTickCount','CountClipboardFormats','GetForeGroundWindow','Isdebuggerpresent','NtGlobalFlag','FindWindow','NtClose',
			  'CloseHandle','OutputDebugString','OutputDebugStringA','OutputDebugStringW','NtQueryInformationProcess',
			  'GetAdaptersInfo','CheckRemoteDebuggerPresent']

#keylogger
keyalerts = ['FindWindowA','ShowWindow','GetAsyncKeyState','SetWindowsHookEx','RegisterHotKey','GetMessage','UnhookWindowsHookEx']

#crypto stuff
cryptalerts = ['CryptEncrypt','CryptAcquireContext','CryptAcquireContext','CryptImportPublicKeyInfo','CryptoAPI']

def Main(filename):
	print("PE check for '%s':" % filename)
	getFileType(filename)
	try:
		pe = pefile.PE(filename)
	except pefile.PEFormatError:
		cprint("\n***************************************", 'red')
		cprint("Aw Snap, invaild format!", 'red')
		cprint("Manual inspection required!", 'red')
		cprint("***************************************\n", 'red')
		sys.exit(1)
	getFileInfo(pe)
	getFileDeclared(pe)
	getFileExports(pe)
	getSectionDetails(pe)
	getFileStats(pe, filename)
   
def getSectionDetails(pe):
	cprint("\n***************************************", 'blue')
	cprint("Getting Sections...", 'blue')
	cprint("***************************************\n", 'blue')
	print("%-10s %-12s %-12s %-12s %-45s %-12s" % ("Name", "VirtAddr", "VirtSize", "RawSize", "SHA-1", "Entropy"))
	print("-" * 120)
	for sec in pe.sections:
		s = "%-10s %-12s %-12s %-12s %-45s %-12f" % (''.join([c for c in str(sec.Name, 'utf-8') if c in string.printable]), 
			hex(sec.VirtualAddress), 
			hex(sec.Misc_VirtualSize), 
			hex(sec.SizeOfRawData),
			sec.get_hash_sha1(),
			sec.get_entropy())
		if sec.SizeOfRawData == 0 or \
			(sec.get_entropy() > 0 and sec.get_entropy() < 1) or \
			sec.get_entropy() > 7:
			s += "[SUSPICIOUS]"
		if s.endswith ("[SUSPICIOUS]"):
			cprint(s, 'red')
		else:
			print(s)

def getFileInfo(pe):
	ped = pe.dump_dict()
	cprint("\n***************************************", 'blue')
	cprint("Compile information:", 'blue')
	cprint("***************************************\n", 'blue')
	#Compile time
	comp_time = ped['FILE_HEADER']['TimeDateStamp']['Value']
	comp_time = comp_time.split("[")[-1].strip("]")
	time_stamp, timezone = comp_time.rsplit(" ", 1)
	comp_time = datetime.strptime(time_stamp, "%a %b %d %H:%M:%S %Y")
	print("Compiled on {} {}".format(comp_time, timezone.strip()))

def getFileDeclared(pe):
	cprint("\n***************************************", 'blue')
	cprint("Functions declared and referenced:", 'blue')
	cprint("***************************************\n", 'blue')
	ret, ret1, ret2, ret3, ret4, ret5, ret6, ret7, ret8 = ([] for i in range(9))

	for lib in pe.DIRECTORY_ENTRY_IMPORT:
		print (str(lib.dll, 'utf-8'))
		for imp in lib.imports:
			if imp.name != None:
				print ('\t' + str(imp.name, 'utf-8'))
			if (imp.name != None) and (imp.name != ""):  
				for alert in regalerts:
					if imp.name.decode('utf-8').startswith(alert):   
						ret.append(imp.name)
				for alert in netalerts:
					if imp.name.decode('utf-8').startswith(alert):   
						ret1.append(imp.name)
				for alert in psalerts:
					if imp.name.decode('utf-8').startswith(alert):   
						ret2.append(imp.name)
				for alert in sysalerts:
					if imp.name.decode('utf-8').startswith(alert):   
						ret3.append(imp.name)
				for alert in dropalerts:
					if imp.name.decode('utf-8').startswith(alert):   
						ret4.append(imp.name)
				for alert in dlinjalerts:
					if imp.name.decode('utf-8').startswith(alert):   
						ret5.append(imp.name)
				for alert in antialerts:
					if imp.name.decode('utf-8').startswith(alert):   
						ret6.append(imp.name)
				for alert in keyalerts:
					if imp.name.decode('utf-8').startswith(alert):   
						ret7.append(imp.name)
				for alert in cryptalerts:
					if imp.name.decode('utf-8').startswith(alert):   
						ret8.append(imp.name)

	if len(ret) != 0:
		cprint("\n***************************************", 'blue')
		cprint("Suspicious registry alerts", 'yellow', attrs=['bold'])
		cprint("***************************************", 'blue')
		for x in ret:
			cprint("\t"+x.decode("utf-8"), 'yellow', attrs=['bold'])

	if len(ret1) != 0:
		cprint("\n***************************************", 'blue')
		cprint("Suspicious network alerts", 'yellow', attrs=['bold'])
		cprint("***************************************", 'blue')
		for x in ret1:
			cprint("\t"+x.decode("utf-8"), 'yellow', attrs=['bold'])

	if len(ret2) != 0:
		cprint("\n***************************************", 'blue')
		cprint("Suspicious process alerts", 'yellow', attrs=['bold'])
		cprint("***************************************", 'blue')
		for x in ret2:
			cprint("\t"+x.decode("utf-8"), 'yellow', attrs=['bold'])

	if len(ret4) != 0:
		cprint("\n***************************************", 'blue')
		cprint("Suspicious dropper alerts", 'yellow', attrs=['bold'])
		cprint("***************************************", 'blue')
		for x in ret4:
			cprint("\t"+x.decode("utf-8"), 'yellow', attrs=['bold'])

	if len(ret5) != 0:
		cprint("\n***************************************", 'blue')
		cprint("Suspicious dll inject alerts", 'yellow', attrs=['bold'])
		cprint("***************************************", 'blue')
		for x in ret5:
			cprint("\t"+x.decode("utf-8"), 'yellow', attrs=['bold'])

	if len(ret7) != 0:
		cprint("\n***************************************", 'blue')
		cprint("Suspicious keylogger debugger/vm alerts", 'yellow', attrs=['bold'])
		cprint("***************************************", 'blue')
		for x in ret7:
			cprint("\t"+x.decode("utf-8"), 'yellow', attrs=['bold'])

	if len(ret3) != 0:
		cprint("\n***************************************", 'blue')
		cprint("Suspicious General IAT alerts", 'yellow', attrs=['bold'])
		cprint("***************************************", 'blue')
		for x in ret3:
			cprint("\t"+x.decode("utf-8"), 'yellow', attrs=['bold'])

	if len(ret8) != 0:
		cprint("\n***************************************", 'blue')
		cprint("Suspicious CRYPTO alerts", 'yellow', attrs=['bold'])
		cprint("***************************************", 'blue')
		for x in ret8:
			cprint("\t"+x.decode("utf-8"), 'yellow', attrs=['bold'])
			
	if len(ret6) != 0:
		cprint("\n***************************************", 'blue')
		cprint("Suspicious anti debugger/vm alerts", 'yellow', attrs=['bold'])
		cprint("***************************************", 'blue')
		for x in ret6:
			cprint("\t"+x.decode("utf-8"), 'yellow', attrs=['bold'])


def getFileExports(pe):
	cprint("\n***************************************", 'blue')
	cprint("Looking for exported sysmbols...", 'blue')
	cprint("***************************************", 'blue')
	try:
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			#print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal
			print("Name: %s, Ordinal number: %i" % (str(exp.name, 'utf-8'), exp.ordinal))
	except:
		cprint("No exported symbols!", 'magenta')


def getFileStats(pe, filename):
	cprint("\n***************************************", 'blue')
	cprint("Getting file statics...", 'blue')
	cprint("***************************************\n", 'blue')
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
		cprint("The entropy value (%s) falls outside the 99%% confidence intervals, manual inspection required!\n" % entropy, 'red')
	print('MD5	 hash: %s' % hashlib.md5(raw).hexdigest())
	print('SHA-1   hash: %s' % hashlib.sha1(raw).hexdigest())
	print('SHA-256 hash: %s' % hashlib.sha256(raw).hexdigest())
	print('SHA-512 hash: %s' % hashlib.sha512(raw).hexdigest())
	print('Import hash (imphash): %s' % pe.get_imphash())
	print('fuzzy hash (ssdeep): %s' % ssdeep.hash_from_file(filename))

def getFileType(filename):
	filetype = magic.from_file(filename)
	cprint("\n***************************************", 'blue')
	cprint("Getting filetype...", 'blue')
	cprint("***************************************\n", 'blue')
	cprint(filetype, 'green')

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='A rapid file analysis tool')
	parser.add_argument("filename", help="The file to be inspected by the tool")
	args = parser.parse_args()
	Main(args.filename)
