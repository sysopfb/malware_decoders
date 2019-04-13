'''
Written by Jason Reaves - @sysopfb
Free to use, attribute properly.

'''

import re
import sys
import struct
import aplib
import binascii
import serpent2
from Crypto.PublicKey import RSA

JOINER_SECTIONS = {0xe1285e64: "CRC_PUBLIC_KEY", 0x8fb1dde1: "CRC_CLIENT_INI", 0xd722afcb: "CRC_CLIENT_INI", 0x4f75cea7: "CRC_LOADER_DLL", 0x90f8aab5: "CRC_LOADER_DLL", 0x7a042a8a: "CRC_INSTALL_INI", 0x90f8aab4: "CRC_CLIENT64", 0xda57d71a: "CRC_WORDLIST", 0xc535d8bf: "CRC_LOADER_DLL"}
INI_PARAMS = {0x4fa8693e: "CRC_SERVERKEY", 0xd0665bf6: "CRC_HOSTS", 0x656b798a: "CRC_GROUP", 0x556aed8f: "CRC_SERVER", 0x11271c7f: "CONF_TIMEOUT", 0x48295783: "CONFIG_FAIL_TIMEOUT", 0xea9ea760: "CRC_BOOTSTRAP", 0x31277bd5: "CRC_TASKTIMEOUT",0x955879a6: "CRC_SENDTIMEOUT", 0x9fd13931: "CRC_BCSERVER", 0x6de85128: "CRC_BCTIMEOUT", 0xacc79a02: "CRC_KNOCKERTIMEOUT", 0x602c2c26: "CRC_KEYLOGLIST", 0x556aed8f: "CRC_SERVER", 0xd7a003c9: "CRC_CONFIGTIMEOUT", 0x18a632bb: "CRC_CONFIGFAILTIMEOUT", 0x73177345: "CRC_DGA_SEED_URL", 0x510f22d2: "CRC_TORSERVER", 0xec99df2e: "CRC_EXTERNALIP", 0xc61efa7a: "CRC_DGATLDS", 0xdf351e24: "CRC_32BITDOWNLOAD", 0x4b214f54: "CRC_64BITDOWNLOAD", 0xcd850e68: "DGA_CRC", 0xdf2e7488: "DGA_COUNT", 0x584e5925: "TIMER"}


class IniParams:
	def __init__(self, count, iniParams):
		self.count = count
		self.ini_params = iniParams
	
	def put_param(self, param):
		self.ini_params.append(param)

	def get_jsonify(self):
		ret_val = {}
		for param in self.ini_params:
			ret_val.update(param.get_jsonify())
		return ret_val
		
	def __str__(self):
		ret_val = ""
		for param in self.ini_params:
			ret_val += str(param)+'\n'
		
		return ret_val

class IniParam:
	def __init__(self, hash, offset, data):
		self.name = "UNKNOWN"
		self.data = ""
		if hash in INI_PARAMS.keys():
			self.name = INI_PARAMS[hash]
		self.data = data[offset:].split('\x00')[0]
		self.hash = hash
	
	def get_name(self):
		return self.name
	def get_data(self):
		return self.data
	
	def get_jsonify(self):
		return({self.name:str(self.data)})

	def __str__(self):
		return(self.name+":"+hex(self.hash)+": "+str(self.data))

def pub_key_parse(data):
	print("PUB KEY:")
	print(binascii.hexlify(data))
	return({"PUB_KEY": binascii.hexlify(data)})

def client_init_parse(keypub,data):
	bits = keypub.size()+1
	encBlock = data[-(bits/8):]
	decBlock = keypub.encrypt(encBlock,0)[0]
	#Code converted from Gozi source
	decBlock = decBlock[2:]
	for i in range(len(decBlock)):
		if decBlock[i] != '\xff':
			decBlock = decBlock[i:]
			break

	#\x00 is separator
	if decBlock[0] == '\x00':
		decBlock=decBlock[1:]

	#New code stores a serp key 16 bytes in
	#checkval = ord(decBlock[0]) - 1
	data_length = len(data[:-(bits/8)]) & 0xfffffff0
	serpKey = decBlock[16:32]

	data = serpent2.serpent_cbc_decrypt(serpKey,data[:-128])

	print("INI PARAMS:")
	count = struct.unpack_from('<I', data)[0]
	params = IniParams(count,[])
	
	data = data[8:]
	for i in range(count):
		(hash,flag,offset,) = struct.unpack_from('<III', data)
		params.put_param(IniParam(hash,offset,data))
		data = data[0x18:]
	
	print(params)
	return(params.get_jsonify())

def convert_pubkey(data):
	pub = aplib.decompress(data).do()[0]
	bit = struct.unpack_from('<I', pub)[0]
	mod = pub[4:(bit/8)+4]
	exp = pub[(bit/8)+4:]

	mod = int(binascii.hexlify(mod),16)
	exp = int(binascii.hexlify(exp),16)
	keypub = RSA.construct((mod, long(exp)))
	pempub = keypub.exportKey('PEM')
	return((keypub, pempub))

def parse_wordlist(data):
	out = aplib.decompress(data).do()[0]
	return({"WORD_LIST": out})

handlers = {"CRC_PUBLIC_KEY": convert_pubkey, "CRC_CLIENT_INI": client_init_parse, "CRC_WORDLIST": parse_wordlist}


def find_xor_table(data):
	ret_val = None
	items = re.split('''[\x00]{40,}''', data)
	items = filter(lambda x: len(x) > 40 and len(x) <100, items)
	for item in items:
		l = struct.unpack_from('<I', item)[0]
		if l == len(item)+4:
			ret_val = item
			break
	return ret_val

config = {}
data = open(sys.argv[1], 'rb').read()
blob = find_xor_table(data)
print(blob)
#off = data.find('\x00\x00WD')
#blob = data[off-2:]
l = struct.unpack_from('<I', blob)[0]
config['CONF_VAL'] = blob[4:6]
blob = blob[8:]+'\x00\x00\x00\x00'
#blob = blob[8:l]
xorval = struct.unpack_from('<I', blob)[0]
client_ini_data = None
keypub = None
while xorval != 0:
	blob = blob[4:]
	(xor_hash, val2, val3,) = struct.unpack_from('<III', blob)
	blob = blob[12:]
	crc_hash = xorval ^ xor_hash
	offset = xorval ^ val3
	l = xorval^val2
	if crc_hash in JOINER_SECTIONS.keys():
		print(JOINER_SECTIONS[crc_hash])
		handler = handlers[JOINER_SECTIONS[crc_hash]]
		if JOINER_SECTIONS[crc_hash] == "CRC_PUBLIC_KEY":
			sect_data = data[offset:offset+l]
			(keypub,pempub) = handler(sect_data)
		elif JOINER_SECTIONS[crc_hash] == "CRC_CLIENT_INI":
			client_ini_data = data[offset:offset+l]
		else:
			if JOINER_SECTIONS[crc_hash] in handlers.keys():
				handler = handlers[JOINER_SECTIONS[crc_hash]]
				sect_data = data[offset:offset+l]
				config.update(handler(sect_data))
	else:
		print("CRC_HASH: "+hex(xorval^xor_hash))
	print("Length: "+hex(xorval^val2))
	print("offset: "+hex(xorval^val3))
	xorval = struct.unpack_from('<I', blob)[0]
	
if type(keypub) != type(None):
	print("Pub key: " +pempub)
	config.update({'PUB_KEY': pempub})
	if client_ini_data != None:
		config.update(client_init_parse(keypub,client_ini_data))
print(config)
	
