#!/usr/bin/env python

"""
CTB-locker infection helper tool PoC
Copyright (C) 2015 - Jos Wetzels.
See the file 'LICENSE' for copying permission.

Proof-of-Concept tool for helping in recovery/decryption of files encrypted using the 'CTB-locker' ransomware family. Run this script on the infected machine.
See http://samvartaka.github.io/malware/2015/11/20/ctb-locker/ for more details.
"""


import ctypes
from _winreg import *
from hashlib import *
from ctypes import wintypes, windll
from struct import pack, unpack

class CTB_Helper:
	def __init__(self):
		return

	def get_common_appdata(self):
		CSIDL_COMMON_APPDATA = 35

		SHGetFolderPath = windll.shell32.SHGetFolderPathW
		SHGetFolderPath.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR]

		path = wintypes.create_unicode_buffer(wintypes.MAX_PATH)
		result = SHGetFolderPath(0, CSIDL_COMMON_APPDATA, 0, 0, path)
		return path.value

	# Corehash DWORD to string
	def dword_to_string(self, a1):
		v1 = []
		v3 = 7
		v2 = a1
		while (v3):
			v4 = v2
			v2 /= 0x1A
			v1.append(chr((v4 % 0x1A) + 97))
			v3 -= 1
		return "".join(v1)

	# Get Cryptographic Machine GUID
	def get_machine_guid(self):
		aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
		aKey = OpenKey(aReg, r"SOFTWARE\\Microsoft\\Cryptography")		
		return QueryValueEx(aKey, "MachineGuid")[0]

	# Calculate Core hash
	def get_core_hash(self):
		return sha256(self.get_machine_guid().replace('-', '').decode('hex')).digest()

	# Dump various info elements
	def dump_info(self):
		corehash = self.get_core_hash()
		dwords = [unpack('<I', corehash[i: i+4])[0] for i in xrange(0, len(corehash), 4)]
		strs = [self.dword_to_string(x) for x in dwords]

		info = {}
		info['hidden_info'] = self.get_common_appdata() + "\\" + strs[0]
		info['corehash'] = corehash.encode('hex')
		return info

helper = CTB_Helper()
print helper.dump_info()