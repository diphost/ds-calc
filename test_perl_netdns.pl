#!/usr/bin/env perl

use Digest::SHA;                # SHA algorithm dependence
use Digest::GOST::CryptoPro;    # GOST algorithm dependence
use Net::DNS::RR::DS;           # recent version Net::DNS >=1.0 needed

# $domain      - string, the canonical domain name with trailing dot
# $flags       - int, the flags of the DNSKEY (alway 257)
# $protocol    - int, the protocol of the DNSKEY (always 3)
# $algorithm   - int, the algorithm of the DNSKEY (5, 7, 8, 10, 12, 13 or 14)
# $publickey   - string, the full publickey base64 encoded (care, no spaces allowed)
# $digest_alg  - string, the hash algorithm for the DS digest (sha1, sha256, gost-crypto or sha384)
#
# return keytag and DS signature as a array
sub calc_ds($$$$$$) {
        my ($domain, $flags, $protocol, $algorithm, $publickey, $digest_alg) = @_;
        # создать объект DNSKEY
        my $string = "$domain DNSKEY $flags $protocol $algorithm $publickey";
        my $rr = Net::DNS::RR->new($string);
        # создать объект DS из DNSKEY
        my $dsrr = create Net::DNS::RR::DS($rr, digtype => $digest_alg);
        return ($dsrr->keytag ,uc $dsrr->digest);
};

# Test with predefined test data
my %dnskey = (
	'domain' => 'example.com.',
	'flags' => '257',
	'protocol' => 3,
	'algorithm' => '13',
	'key' => "6a81escFb5QysOzJopVCPslEyldHJxOlNIq3ol0xZPeLn6HBLwdRIaxz1aYpefJHPaj+seBti4j5gLWYetY3vA==",
);

my ($keytag, $digest) = ();
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'SHA1');
print("REF:    example.com. IN DS 20545 13 1 40BD7CF025EEB433F9E74127009BD0AF8C16F449\n");
print("CALC:   $dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 1 $digest\n\n");
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'SHA256');
print("REF:    example.com. IN DS 20545 13 2 E460EAB7D69ABDE51078BC27CE8377074CA94EE05F5A609E5593C5E25ACF2BF4\n");
print("CALC:   $dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 2 $digest\n\n");
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'GOST');
print("REF:    example.com. IN DS 20545 13 3 9B8E8392B2C8203CEC672AE891329221678CE06E5FE861DB61688F0C1CA0B494\n");
print("CALC:   $dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 3 $digest\n\n");
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'SHA384');
print("REF:    example.com. IN DS 20545 13 4 99436F3FB883CA4F077798C206037D97A34560245E57F1FFB10222B12AB8BD73755B1C41BFF6CF039E942CD3CB3950C1\n");
print("CALC:   $dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 4 $digest\n");

