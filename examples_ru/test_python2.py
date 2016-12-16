#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
import hashlib
import base64
from pygost.gost341194 import GOST341194        # https://pypi.python.org/pypi/pygost/ >=3.0
from pygost.utils import hexenc                 # для хэша ГОСТ 34.11-94

# owner         - string, каноническое имя домена с точкой на конце
# flags         - int, флаги DNSKEY (для KSK всегда 257)
# protocol      - int, протокол DNSKEY (всегда 3)
# algorithm     - int, алгоритм ключа DNSKEY (5, 7, 8, 10, 12, 13 или 14)
# publickey     - string, публичная часть ключа DNSKEY в base64 кодировке (без пробелов)
# digest_alg    - string, алгоритм отпечатка для DS (sha1, sha256, gost-crypto или sha384)
#
# возвращает список (tuple), состоящий из keytag и отпечатка DS
def calc_ds(owner, flags, protocol, algorithm, publickey, digest_alg):
        # сформировать бинарную DNSKEY RDATA
        dnskey_rdata = struct.pack('!HBB', int(flags), int(protocol), int(algorithm))
        dnskey_rdata += base64.b64decode(publickey)
        # вычислить контрольную сумму keytag
        crc = 0
        for i in xrange(len(dnskey_rdata)):
                b = struct.unpack('B', dnskey_rdata[i])[0]
                crc += b if i & 1 else b << 8
        keytag = ((crc & 0xFFFF) + ((crc >> 16) & 0xFFFF)) & 0xFFFF
        # сформировать бинарный вид доменного имени
        domain_wire_format = ''
        for part in owner.split('.'):
                domain_wire_format += struct.pack('B', len(part))+part
        # создать отпечаток требуемого типа
        if digest_alg == 'sha1':
                digest = hashlib.sha1(domain_wire_format + dnskey_rdata).hexdigest().upper()
        if digest_alg == 'sha256':
                digest = hashlib.sha256(domain_wire_format + dnskey_rdata).hexdigest().upper()
        if digest_alg == 'gost-crypto':
                digest = GOST341194(domain_wire_format + dnskey_rdata, "GostR3411_94_CryptoProParamSet").hexdigest().upper()
        if digest_alg == 'sha384':
                digest = hashlib.sha384(domain_wire_format + dnskey_rdata).hexdigest().upper()
        return (keytag, digest)

# Проверка на тестовых данных
if __name__ == "__main__":
        dnskey = {
                'domain':'example.com.',
                'flags':'257',
                'protocol':3,
                'algorithm':13,
                'key':"6a81escFb5QysOzJopVCPslEyldHJxOlNIq3ol0xZPeLn6HBLwdRIaxz1aYpefJHPaj+seBti4j5gLWYetY3vA==",
        };
        (keytag, digest) = calc_ds(dnskey['domain'], dnskey['flags'], dnskey['protocol'], dnskey['algorithm'], dnskey['key'], 'sha1');
        print(u"ЭТАЛОН:    example.com. IN DS 20545 13 1 40BD7CF025EEB433F9E74127009BD0AF8C16F449")
        print(u"ВЫЧИСЛЕНО: %s IN DS %d %d 1 %s\n" % (dnskey['domain'], keytag, dnskey['algorithm'], digest))
        (keytag, digest) = calc_ds(dnskey['domain'], dnskey['flags'], dnskey['protocol'], dnskey['algorithm'], dnskey['key'], 'sha256');
        print(u"ЭТАЛОН:    example.com. IN DS 20545 13 2 E460EAB7D69ABDE51078BC27CE8377074CA94EE05F5A609E5593C5E25ACF2BF4")
        print(u"ВЫЧИСЛЕНО: %s IN DS %d %d 2 %s\n" % (dnskey['domain'], keytag, dnskey['algorithm'], digest))
        (keytag, digest) = calc_ds(dnskey['domain'], dnskey['flags'], dnskey['protocol'], dnskey['algorithm'], dnskey['key'], 'gost-crypto');
        print(u"ЭТАЛОН:    example.com. IN DS 20545 13 3 9B8E8392B2C8203CEC672AE891329221678CE06E5FE861DB61688F0C1CA0B494")
        print(u"ВЫЧИСЛЕНО: %s IN DS %d %d 3 %s\n" % (dnskey['domain'], keytag, dnskey['algorithm'], digest))
        (keytag, digest) = calc_ds(dnskey['domain'], dnskey['flags'], dnskey['protocol'], dnskey['algorithm'], dnskey['key'], 'sha384');
        print(u"ЭТАЛОН:    example.com. IN DS 20545 13 4 99436F3FB883CA4F077798C206037D97A34560245E57F1FFB10222B12AB8BD73755B1C41BFF6CF039E942CD3CB3950C1")
        print(u"ВЫЧИСЛЕНО: %s IN DS %d %d 4 %s\n" % (dnskey['domain'], keytag, dnskey['algorithm'], digest))

