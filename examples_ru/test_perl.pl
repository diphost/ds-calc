#!/usr/bin/env perl

use strict;
use MIME::Base64;
use Digest::SHA;                # зависимость для SHA
use Digest::GOST::CryptoPro;    # зависимость для ГОСТ 34.11-94

# $domain      - string, каноническое имя домена с точкой на конце
# $flags       - int, флаги DNSKEY (для KSK всегда 257)
# $protocol    - int, протокол DNSKEY (всегда 3)
# $algorithm   - int, алгоритм ключа DNSKEY (5, 7, 8, 10, 12, 13 или 14)
# $publickey   - string, публичная часть ключа DNSKEY в base64 кодировке (без пробелов)
# $digest_alg  - string, алгоритм отпечатка для DS (sha1, sha256, gost-crypto или sha384)
#
# возвращает массив, состоящий из keytag и отпечатка DS
sub calc_ds($$$$$$) {
        my ($domain, $flags, $protocol, $algorithm, $publickey, $digest_alg) = @_;
        # сформировать бинарную DNSKEY RDATA
        my $dnskey_rdata = pack('nCC', $flags, $protocol, $algorithm);
	$dnskey_rdata .= decode_base64($publickey);
        # вычислить контрольную сумму keytag
	my $crc = 0;
	for(my $i = 0; $i < length($dnskey_rdata); $i++) {
		my $b = ord(substr $dnskey_rdata, $i, 1);
		$crc += ($i & 1) ? $b : $b << 8;
	};
	my $keytag = (($crc & 0xffff) + (($crc >> 16) & 0xffff)) & 0xffff;
        # сформировать бинарный вид доменного имени
	my @parts = split(/\./, $domain, -1);
	my $domain_wire_format = '';
	foreach my $part (@parts) {
		$domain_wire_format .= pack('C', length $part ) . $part;
	};
        # создать отпечаток требуемого типа
	return $keytag, uc Digest::SHA::sha1_hex($domain_wire_format . $dnskey_rdata) if $digest_alg eq 'SHA1';
        return $keytag, uc Digest::SHA::sha256_hex($domain_wire_format . $dnskey_rdata) if $digest_alg eq 'SHA256';
        return $keytag, uc Digest::GOST::CryptoPro::gost_hex($domain_wire_format . $dnskey_rdata) if $digest_alg eq 'GOST';
	return $keytag, uc Digest::SHA::sha384_hex($domain_wire_format . $dnskey_rdata) if $digest_alg eq 'SHA384';
};

# Проверка на тестовых данных
my %dnskey = (
	'domain' => 'example.com.',
	'flags' => '257',
	'protocol' => 3,
	'algorithm' => '13',
	'key' => "6a81escFb5QysOzJopVCPslEyldHJxOlNIq3ol0xZPeLn6HBLwdRIaxz1aYpefJHPaj+seBti4j5gLWYetY3vA==",
);

my ($keytag, $digest) = ();
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'SHA1');
print("ЭТАЛОН:    example.com. IN DS 20545 13 1 40BD7CF025EEB433F9E74127009BD0AF8C16F449\n");
print("ВЫЧИСЛЕНО: $dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 1 $digest\n\n");
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'SHA256');
print("ЭТАЛОН:    example.com. IN DS 20545 13 2 E460EAB7D69ABDE51078BC27CE8377074CA94EE05F5A609E5593C5E25ACF2BF4\n");
print("ВЫЧИСЛЕНО: $dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 2 $digest\n\n");
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'GOST');
print("ЭТАЛОН:    example.com. IN DS 20545 13 3 9B8E8392B2C8203CEC672AE891329221678CE06E5FE861DB61688F0C1CA0B494\n");
print("ВЫЧИСЛЕНО: $dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 3 $digest\n\n");
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'SHA384');
print("ЭТАЛОН:    example.com. IN DS 20545 13 4 99436F3FB883CA4F077798C206037D97A34560245E57F1FFB10222B12AB8BD73755B1C41BFF6CF039E942CD3CB3950C1\n");
print("ВЫЧИСЛЕНО: $dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 4 $digest\n");

