#!/usr/bin/env python

"""
CTB-locker file decryption tool PoC
Copyright (C) 2015 - Jos Wetzels.
See the file 'LICENSE' for copying permission.

Proof-of-Concept tool for decryption of files encrypted using the 'CTB-locker' ransomware family provided we have the master private key.
See http://samvartaka.github.io/malware/2015/11/20/ctb-locker/ for more details.

Requires:
	https://pypi.python.org/pypi/pycrypto
	https://github.com/TomCrypto/pycurve25519
"""

import argparse
import os
import zlib
import curve25519
from Crypto.Cipher import AES
from hashlib import *
from struct import pack

class CTB_Cracker:
	def __init__(self):
		return

	# CTB-locker deflate-compresses at compression level 3
	def inflate(self, data):
		return zlib.decompress(data, -15)

	# Divide input into blocks
	def get_blocks(self, data, block_size):
		return [data[i:i+block_size] for i in range(0, len(data), block_size)]

	# Decrypt AES block
	def AES_decrypt(self, ciphertext_block, aes_key):
		return AES.AESCipher(aes_key, AES.MODE_ECB).decrypt(ciphertext_block)

	# AES-256-ECB
	def AES_decrypt_ECB(self, ciphertext, aes_key):
		blocks = self.get_blocks(ciphertext, 16)
		p = ""
		for b in blocks:
			p += self.AES_decrypt(b, aes_key)
		return p

	# Decrypt hidden info file
	def decrypt_hiddeninfo(self, data, aes_key):
		data = list(data)

		assert (len(data) == 0x28E), "[-] HiddenInfo file has to be 0x28E bytes"

		# Advance counter byte-by-byte
		for i in xrange(0, len(data)-15, 1):
			data[len(data)-i-16:len(data)-i] = list(self.AES_decrypt("".join(data[len(data)-i-16:len(data)-i]), aes_key))

		return "".join(data)

	# Decrypt secret info section of hidden info file
	def decrypt_secretinfo(self, data, public_key_2, master_private_key):
		data = list(data)

		assert (len(data) == 0x28), "[-] SecretInfo section has to be 0x28 bytes"

		shared_secret = curve25519.shared(master_private_key, public_key_2)
		aes_key = sha256(shared_secret).digest()

		# Advance counter 4 bytes at a time
		for counter in xrange(0, len(data)-15, 4):
			data[len(data)-i-16:len(data)-i] = list(self.AES_decrypt("".join(data[len(data)-i-16:len(data)-i]), aes_key))

		p = "".join(data)
		return p[0:32], p[32:40]

	# Decrypt, verify & parse hidden info file
	def parse_hiddeninfo(self, hidden_info_filename, hidden_info_key, master_private_key=None):
		p = self.decrypt_hiddeninfo(open(hidden_info_filename, "rb").read(), hidden_info_key)

		hidden_info = {}

		hidden_info['pubkey1'] = p[0:32]
		hidden_info['pubkey2'] = p[36:68]
		if(master_private_key):
			hidden_info['seckey1'], hidden_info['machineguid'] = self.decrypt_secretinfo(p[68:108], hidden_info['pubkey2'], master_private_key)
		else:
			hidden_info['seckey1'], hidden_info['machineguid'] = None, None
		hidden_info['demokeys'] = [p[0xEC+(i*32):0xEC+((i+1)*32)] for i in xrange(5)]
		hidden_info['payment_server'] = p[0xCA: 0xCA+p[0xCA:].find(".onion")+6]
		return hidden_info

	# Dump hidden info
	def dump_hiddeninfo(self, hidden_info):
		print "[+] Dumping hiddeninfo:"
		print "[+] Public Key 1: [%s]" % hidden_info['pubkey1'].encode('hex')
		print "[+] Public Key 2: [%s]" % hidden_info['pubkey2'].encode('hex')
		for i in xrange(5):
			print "[+] Demo Secret Key %d: [%s]" % (i, hidden_info['demokeys'][i].encode('hex'))
		print "[+] Payment Server: [%s]" % hidden_info['payment_server']
		return

	# Recover encrypted file
	def recover_encrypted_file(self, tdir, rdir, encrypted_file, secret_key):
		data = open(tdir + "/" + encrypted_file, "rb").read()
		file_pubkey = data[:32]
		file_infovec_c = data[32: 32+16]
		file_ciphertext = data[32+16: ]

		file_shared_secret = curve25519.shared(secret_key, file_pubkey)
		file_aes_key = sha256(file_shared_secret).digest()

		file_infovec_p = self.AES_decrypt(file_infovec_c, file_aes_key)

		if((file_infovec_p[0:4] != 'CTB1') or (file_infovec_p[12:16] != pack('<I', 1))):
			return False

		file_plaintext = self.inflate(AES_decrypt_ECB(file_ciphertext, file_aes_key))

		x = encrypted_file.split('.')
		orig_filename = '.'.join(x[:len(x)-1])
		f = open(rdir + "/" + orig_filename, "wb")
		f.write(file_plaintext)
		f.close()
		return True

	# Recover encrypted files in directory
	def recover_directory(self, tdir, rdir, secret_key):
		for dir_name, subdir_list, file_list in os.walk(tdir):
			for file_name in file_list:
				if(self.recover_encrypted_file(tdir, rdir, file_name, secret_key)):
					print "[+] Recovered file '%s'" % (file_name)
				else:
					print "[-] Failed to recover file '%s'" % (file_name)
		return

class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        print "[-]Error: %s\n" % message
        self.print_help()
        exit()

def get_arg_parser():
	header = ""

	parser = ArgParser(description=header)	
	parser.add_argument('--hiddeninfo', dest='hiddeninfo', help='hiddeninfo file', required=True)
	parser.add_argument('--corehash', dest='corehash', help='corehash (in hex)', required=True)
	parser.add_argument('--masterprivatekey', dest='masterprivatekey', help='master private key (in hex)')
	parser.add_argument('--tdir', dest='tdir', help='folder containing encrypted files', required=True)
	parser.add_argument('--rdir', dest='rdir', help='folder to store decrypted files', required=True)

	return parser

banner = "\t.CTB-locker file decryption tool.\n\t\t(c) 2015, Jos Wetzels\n"
print banner

parser = get_arg_parser()
args = parser.parse_args()

cracker = CTB_Cracker()
if(args.masterprivatekey):
	hidden_info = cracker.parse_hiddeninfo(args.hiddeninfo, args.corehash.decode('hex'), args.masterprivatekey.decode('hex'))
else:
	hidden_info = cracker.parse_hiddeninfo(args.hiddeninfo, args.corehash.decode('hex'))
if(hidden_info['seckey1']):
	cracker.recover_directory(args.tdir, args.rdir, hidden_info['seckey1'])
else:
	print "[-] No master private key supplied, could not recover secretinfo"
	cracker.dump_hiddeninfo(hidden_info)