#!/usr/bin/env python

"""
CTB-locker memory hunter tool PoC
Copyright (C) 2015 - Jos Wetzels.
See the file 'LICENSE' for copying permission.

Proof-of-Concept tool for detecting remnant Curve25519 keypairs in 'CTB-locker' ransomware family memory dumps.
See http://samvartaka.github.io/malware/2015/11/20/ctb-locker/ for more details.

Requires:
	https://github.com/TomCrypto/pycurve25519
"""

import argparse
import curve25519

from struct import pack, unpack

class CTB_Memhunter:
	def __init__(self, dump_file):
		f = open(dump_file, "rb")
		self.data = f.read()
		f.close()
		return

	def hunt_keypairs(self, distance):
		f = False
		for i in xrange(len(self.data)-(distance + 32)):
			a = self.data[i:i+32]
			b = self.data[i+32+distance:i+32+distance+32]
			# Rule out nullkeys
			if ((a == "\x00"*32) or (b == "\x00"*32)):
				continue		
			if (b == curve25519.public(a)):
				print "[+]Found candidate ephemeral keypair!\nSecret: [%s]\nPublic: [%s]" % (a.encode('hex'), b.encode('hex'))
				f = True
			if (a == curve25519.public(b)):
				print "[+]Found candidate ephemeral keypair!\nSecret: [%s]\nPublic: [%s]" % (b.encode('hex'), a.encode('hex'))
				f = True

		if not(f):
			print "[-]Found no remnant ephemeral keypairs..."
		return

class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        print "[-]Error: %s\n" % message
        self.print_help()
        exit()

def get_arg_parser():
	header = ""

	parser = ArgParser(description=header)	
	parser.add_argument('--dumpfile', dest='dumpfile', help='memory dumpfile to analyze', required=True)
	parser.add_argument('--distance', dest='distance', help='distance between keys', type=int, default=0x70)

	return parser

banner = "\t.CTB-locker memory dump analyzer.\n\t\t(c) 2015, Jos Wetzels\n"
print banner

parser = get_arg_parser()
args = parser.parse_args()

hunter = CTB_Memhunter(args.dumpfile)
hunter.hunt_keypairs(args.distance)