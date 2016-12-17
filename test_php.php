<?php

/*
 * $domain      - string, the canonical domain name with trailing dot
 * $flags       - int, the flags of the DNSKEY (always 257)
 * $protocol    - int, the protocol of the DNSKEY (always 3)
 * $algorithm   - int, the algorithm of the DNSKEY (8, 10, 12, 13 or 14)
 * $publickey   - string publickey, the full publickey base64 encoded (care, no spaces allowed)
 * $digest_alg  - string, the hash algorithm for the DS digest (sha256, gost-crypto or sha384)
 *
 * return keytag and DS signature as a array
 *
 * Warning: minimum php >= 5.6 for gost-crypto hash
*/
function calc_ds($domain, $flags, $protocol, $algorithm, $publickey, $digest_alg) {
        # pack DNSKEY RDATA to wire format
	$dnskey_rdata = pack('nCC', intval($flags), intval($protocol), intval($algorithm));
	$dnskey_rdata .= base64_decode($publickey);
        # calculate keytag
	$crc = 0;
	for($i = 0; $i < strlen($dnskey_rdata); $i++) {
		$b = ord($dnskey_rdata[$i]);
		$crc += ($i & 1) ? $b : $b << 8;
	};
	$keytag = 0xffff & ($crc + ($crc >> 16));
        # pack owner name to wire format
	$parts = explode(".", $domain);
	$domain_wire_format = '';
	foreach ($parts as $part) {
		$domain_wire_format .= pack('C',strlen($part)).$part;
	};
        # calculate digest
        return array($keytag, strtoupper(hash($digest_alg, $domain_wire_format . $dnskey_rdata)));
};

# Test with predefined test data
$dnskey = array(
	'domain' => 'example.com.',
	'flags' => '257',
	'protocol' => 3,
	'algorithm' => '13',
	'key' => "6a81escFb5QysOzJopVCPslEyldHJxOlNIq3ol0xZPeLn6HBLwdRIaxz1aYpefJHPaj+seBti4j5gLWYetY3vA==",
);

list($keytag, $digest) = calc_ds($dnskey['domain'], $dnskey['flags'], $dnskey['protocol'], $dnskey['algorithm'], $dnskey['key'],'sha256');
print("REF:    example.com. IN DS 20545 13 2 E460EAB7D69ABDE51078BC27CE8377074CA94EE05F5A609E5593C5E25ACF2BF4\n");
print("CALC:   " . $dnskey['domain'] ." IN DS $keytag ". $dnskey['algorithm'] . " 2 $digest\n\n");
list($keytag, $digest) = calc_ds($dnskey['domain'], $dnskey['flags'], $dnskey['protocol'], $dnskey['algorithm'], $dnskey['key'],'gost-crypto');
print("REF:    example.com. IN DS 20545 13 3 9B8E8392B2C8203CEC672AE891329221678CE06E5FE861DB61688F0C1CA0B494\n");
print("CACL:   " . $dnskey['domain'] ." IN DS $keytag ". $dnskey['algorithm'] . " 3 $digest\n\n");
list($keytag, $digest) = calc_ds($dnskey['domain'], $dnskey['flags'], $dnskey['protocol'], $dnskey['algorithm'], $dnskey['key'],'sha384');
print("REF:    example.com. IN DS 20545 13 4 99436F3FB883CA4F077798C206037D97A34560245E57F1FFB10222B12AB8BD73755B1C41BFF6CF039E942CD3CB3950C1\n");
print("CACL:   " . $dnskey['domain'] ." IN DS $keytag ". $dnskey['algorithm'] . " 4 $digest\n");
?>

