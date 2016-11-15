#!/usr/bin/env python3

# -*- coding: utf-8 -*-

import struct
import hashlib
import base64
from pygost.gost3411_94 import GOST341194       # https://pypi.python.org/pypi/pygost/
from pygost.utils import hexenc                 # для хэша ГОСТ 34.11-94

# owner         - string, каноническое имя домена с точкой на конце
# flags         - int, флаги DNSKEY (для KSK всегда 257)
# protocol      - int, протокол DNSKEY (всегда 3)
# algorithm     - int, алгоритм ключа DNSKEY (only 3, 5, 6, 7, 8, 10, 12, 13 или 14)
# publickey     - string, публичная часть ключа DNSKEY в base64 кодировке (без пробелов)
# digest_alg    - string, алгоритм отпечатка для DS (sha1, sha256, gost-crypto или sha384)
#
# возвращает массив, состоящий из keytag и отпечатка DS
def calc_ds(owner, flags, protocol, algorithm, publickey, digest_alg):
        dnskey_rdata = struct.pack('!HBB', int(flags), int(protocol), int(algorithm))
        dnskey_rdata += base64.b64decode(publickey)
        crc = 0
        for i in range(len(dnskey_rdata)):
                b = struct.unpack('B', dnskey_rdata[i:i+1])[0]
                crc += b if i & 1 else b << 8
        keytag = ((crc & 0xFFFF) + (crc >> 16)) & 0xFFFF
        domain_wire_format = b''
        for part in bytes(owner,'ascii').split(b'.'):
                domain_wire_format += struct.pack('B', len(part)) + part
        if digest_alg == 'sha1':
                digest = hashlib.sha1(domain_wire_format + dnskey_rdata).hexdigest().upper()
        if digest_alg == 'sha256':
                digest = hashlib.sha256(domain_wire_format + dnskey_rdata).hexdigest().upper()
        if digest_alg == 'gost-crypto':
                digest = hexenc(GOST341194(domain_wire_format + dnskey_rdata, "GostR3411_94_CryptoProParamSet").digest()[::-1]).upper()
        if digest_alg == 'sha384':
                digest = hashlib.sha384(domain_wire_format + dnskey_rdata).hexdigest().upper()
        return (keytag, digest)

dnskey = {
	'domain':'example.com.',
	'flags':'257',
	'protocol':3,
	'algorithm':13,
	'key':"6a81escFb5QysOzJopVCPslEyldHJxOlNIq3ol0xZPeLn6HBLwdRIaxz1aYpefJHPaj+seBti4j5gLWYetY3vA==",
};

(keytag, digest) = calc_ds(dnskey['domain'], dnskey['flags'], dnskey['protocol'], dnskey['algorithm'], dnskey['key'], 'sha1');
print("%s IN DS %d %d 1 %s; test: 20545 13 1 40bd7cf025eeb433f9e74127009bd0af8c16f449\n" % (dnskey['domain'], keytag, dnskey['algorithm'], digest))
(keytag, digest) = calc_ds(dnskey['domain'], dnskey['flags'], dnskey['protocol'], dnskey['algorithm'], dnskey['key'], 'sha256');
print("%s IN DS %d %d 3 %s; test: 20545 13 2 e460eab7d69abde51078bc27ce8377074ca94ee05f5a609e5593c5e25acf2bf4\n" % (dnskey['domain'], keytag, dnskey['algorithm'], digest))
(keytag, digest) = calc_ds(dnskey['domain'], dnskey['flags'], dnskey['protocol'], dnskey['algorithm'], dnskey['key'], 'gost-crypto');
print("%s IN DS %d %d 3 %s; test: 20545 13 3 9b8e8392b2c8203cec672ae891329221678ce06e5fe861db61688f0c1ca0b494\n" % (dnskey['domain'], keytag, dnskey['algorithm'], digest))
(keytag, digest) = calc_ds(dnskey['domain'], dnskey['flags'], dnskey['protocol'], dnskey['algorithm'], dnskey['key'], 'sha384');
print("%s IN DS %d %d 4 %s; test: 20545 13 4 99436f3fb883ca4f077798c206037d97a34560245e57f1ffb10222b12ab8bd73755b1c41bff6cf039e942cd3cb3950c1\n"% (dnskey['domain'], keytag, dnskey['algorithm'], digest))

