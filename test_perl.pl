#!/usr/bin/env perl

use strict;
use MIME::Base64;
use Digest::SHA;                # SHA algorithms dependence
use Digest::GOST::CryptoPro;    # GOST 34.11-94 hash dependence

# $domain      - string, the canonical domain name with trailing dot
# $flags       - int, the flags of the DNSKEY (alway 257)
# $protocol    - int, the protocol of the DNSKEY (always 3)
# $algorithm   - int, the algorithm of the DNSKEY (8, 10, 12, 13 or 14)
# $publickey   - string, the full publickey base64 encoded (care, no spaces allowed)
# $digest_alg  - string, the hash algorithm for the DS digest (sha256, gost-crypto or sha384)
#
# return keytag and DS signature as a array
sub calc_ds($$$$$$) {
        my ($domain, $flags, $protocol, $algorithm, $publickey, $digest_alg) = @_;
        # pack DNSKEY RDATA to wire format
        my $dnskey_rdata = pack('nCC', $flags, $protocol, $algorithm);
	$dnskey_rdata .= decode_base64($publickey);
        # calculate keytag
	my $crc = 0;
	for(my $i = 0; $i < length($dnskey_rdata); $i++) {
		my $b = ord(substr $dnskey_rdata, $i, 1);
		$crc += ($i & 1) ? $b : $b << 8;
	};
	my $keytag = (($crc & 0xffff) + (($crc >> 16) & 0xffff)) & 0xffff;
        # pack owner name to wire format
	my @parts = split(/\./, $domain, -1);
	my $domain_wire_format = '';
	foreach my $part (@parts) {
		$domain_wire_format .= pack('C', length $part ) . $part;
	};
        # calculate digest
        return $keytag, uc Digest::SHA::sha256_hex($domain_wire_format . $dnskey_rdata) if $digest_alg eq 'SHA256';
        return $keytag, uc Digest::GOST::CryptoPro::gost_hex($domain_wire_format . $dnskey_rdata) if $digest_alg eq 'GOST';
	return $keytag, uc Digest::SHA::sha384_hex($domain_wire_format . $dnskey_rdata) if $digest_alg eq 'SHA384';
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
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'SHA256');
print("REF:    example.com. IN DS 20545 13 2 E460EAB7D69ABDE51078BC27CE8377074CA94EE05F5A609E5593C5E25ACF2BF4\n");
print("CALC:   $dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 2 $digest\n\n");
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'GOST');
print("REF:    example.com. IN DS 20545 13 3 9B8E8392B2C8203CEC672AE891329221678CE06E5FE861DB61688F0C1CA0B494\n");
print("CALC:   $dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 3 $digest\n\n");
($keytag, $digest) = calc_ds($dnskey{'domain'}, $dnskey{'flags'}, $dnskey{'protocol'}, $dnskey{'algorithm'}, $dnskey{'key'}, 'SHA384');
print("REF:    example.com. IN DS 20545 13 4 99436F3FB883CA4F077798C206037D97A34560245E57F1FFB10222B12AB8BD73755B1C41BFF6CF039E942CD3CB3950C1\n");
print("CALC:   $dnskey{'domain'} IN DS $keytag $dnskey{'algorithm'} 4 $digest\n");

