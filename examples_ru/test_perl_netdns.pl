#!/usr/bin/env perl

use Digest::SHA;                # зависимость для SHA
use Digest::GOST::CryptoPro;    # зависимость для хэша ГОСТ 34.11-94
use Net::DNS::RR::DS;           # для корректной работы требуется свежая версия Net::DNS >= 1.0

# $domain      - string, каноническое имя домена с точкой на конце
# $flags       - int, флаги DNSKEY (для KSK всегда 257)
# $protocol    - int, протокол DNSKEY (всегда 3)
# $algorithm   - int, алгоритм ключа DNSKEY (only 3, 5, 6, 7, 8, 10, 12, 13 или 14)
# $publickey   - string, публичная часть ключа DNSKEY в base64 кодировке (без пробелов)
# $digest_alg   - string, алгоритм отпечатка для DS (sha1, sha256, gost-crypto или sha384)
#
# возвращает массив, состоящий из keytag и отпечатка DS
sub calc_ds($$$$$$) {
        my ($domain, $flags, $protocol, $algorithm, $publickey, $digest_alg) = @_;
        my $string = "$domain DNSKEY $flags $protocol $algorithm $publickey";
        my $rr = Net::DNS::RR->new($string);
        my $dsrr = create Net::DNS::RR::DS($rr, digtype => $digest_alg);
        return ($dsrr->keytag ,$dsrr->digest);
};

%dnskey = (
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

