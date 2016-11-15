#!/usr/bin/env perl

use Digest::SHA;                # SHA algorithm dependence
use Digest::GOST::CryptoPro;    # GOST algorithm dependence
use Net::DNS::RR::DS;           # recent version Net::DNS >=1.0 needed

# $domain      - string, the canonical domain name with trailing dot
# $flags       - int flags, the flags of the DNSKEY (only 257)
# $protocol    - int protocol, the protocol of the DNSKEY (only 3)
# $algorithm   - int algoritm, the algorithm of the DNSKEY (only 3, 5, 6, 7, 8, 10, 12, 13 or 14)
# $publickey   - string publickey, the full publickey base64 encoded (care, no spaces allowed)
# $digest_alg  - string, the hash algorithm for the DS digest (sha1, sha256, gost-crypto or sha384)
#
# return keytag and DS signature as a array
sub calc_ds($$$$$$) {
        my ($domain, $flags, $protocol, $algorithm, $publickey, $digest) = @_;
        my $string = "$domain DNSKEY $flags $protocol $algorithm $publickey";
        my $rr = Net::DNS::RR->new($string);
        my $dsrr = create Net::DNS::RR::DS($rr, digtype => $digest);
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

