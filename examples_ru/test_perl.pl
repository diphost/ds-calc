#!/usr/bin/env perl

use strict;
use MIME::Base64;
use Digest::SHA;                # зависимость для SHA
use Digest::GOST::CryptoPro;    # зависимость для ГОСТ

# $domain      - string, каноническое имя домена с точкой на конце
# $flags       - int, флаги DNSKEY (для KSK всегда 257)
# $protocol    - int, протокол DNSKEY (всегда 3)
# $algorithm   - int, алгоритм ключа DNSKEY (only 3, 5, 6, 7, 8, 10, 12, 13 или 14)
# $publickey   - string, публичная часть ключа DNSKEY в base64 кодировке (без пробелов)
# $digest_alg  - string, алгоритм отпечатка для DS (sha1, sha256, gost-crypto или sha384)
#
# возвращает массив, состоящий из keytag и отпечатка DS
sub calc_ds($$$$$$) {
        my ($domain, $flags, $protocol, $algorithm, $publickey, $digest_alg) = @_;
        my $dnskey_rdata = pack('nCC', $flags, $protocol, $algorithm);
	$dnskey_rdata .= decode_base64($publickey);
	my $crc = 0;
	for(my $i = 0; $i < length($dnskey_rdata); $i++) {
		my $b = ord(substr $dnskey_rdata, $i, 1);
		$crc += ($i & 1) ? $b : $b << 8;
	};
	my $keytag =  0xffff & ($crc + ($crc >> 16));
	my @parts = split(/\./, $domain, -1);
	my $domain_wire_format = '';
	foreach my $part (@parts) {
		$domain_wire_format .= pack('C', length $part ) . $part;
	};
	return $keytag, uc Digest::SHA::sha1_hex($domain_wire_format . $dnskey_rdata) if $digest_alg eq 'SHA1';
        return $keytag, uc Digest::SHA::sha256_hex($domain_wire_format . $dnskey_rdata) if $digest_alg eq 'SHA256';
        return $keytag, uc Digest::GOST::CryptoPro::gost_hex($domain_wire_format . $dnskey_rdata) if $digest_alg eq 'GOST';
	return $keytag, uc Digest::SHA::sha384_hex($domain_wire_format . $dnskey_rdata) if $digest_alg eq 'SHA384';
};

my %dnskey = (
	'domain' => 'example.com.',
	'flags' => '257',
	'protocol' => 3,
	'algorithm' => '13',
	'key' => "6a81escFb5QysOzJopVCPslEyldHJxOlNIq3ol0xZPeLn6HBLwdRIaxz1aYpefJHPaj+seBti4j5gLWYetY3vA==",
);

my ($keytag, $digest) = ();
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'SHA1');
print "$dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 1 $digest; test: 20545 13 1 40bd7cf025eeb433f9e74127009bd0af8c16f449\n";
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'SHA256');
print "$dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 2 $digest; test: 20545 13 2 e460eab7d69abde51078bc27ce8377074ca94ee05f5a609e5593c5e25acf2bf4\n";
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'GOST');
print "$dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 3 $digest; test: 20545 13 3 9b8e8392b2c8203cec672ae891329221678ce06e5fe861db61688f0c1ca0b494\n";
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'SHA384');
print "$dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 4 $digest; test: 20545 13 4 99436f3fb883ca4f077798c206037d97a34560245e57f1ffb10222b12ab8bd73755b1c41bff6cf039e942cd3cb3950c1\n";

