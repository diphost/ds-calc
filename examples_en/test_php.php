<?php

/*
 * $domain      - string, the canonical domain name with trailing dot
 * $flags       - int flags, the flags of the DNSKEY (only 257)
 * $protocol    - int protocol, the protocol of the DNSKEY (only 3)
 * $algorithm   - int algoritm, the algorithm of the DNSKEY (only 3, 5, 6, 7, 8, 10, 12, 13 or 14)
 * $publickey   - string publickey, the full publickey base64 encoded (care, no spaces allowed)
 * $digest_alg  - string, the hash algorithm for the DS digest (sha1, sha256, gost-crypto or sha384)
 *
 * return keytag and DS signature as a array
 *
 * Warning: minimum php >= 5.6 for gost-crypto hash
*/
function calc_ds($domain, $flags, $protocol, $algorithm, $publickey, $digest_alg) {
	$dnskey_rdata = pack('nCC', intval($flags), intval($protocol), intval($algorithm));
	$dnskey_rdata .= base64_decode($publickey);
	$crc = 0;
	for($i = 0; $i < strlen($dnskey_rdata); $i++) {
		$b = ord($dnskey_rdata[$i]);
		$crc += ($i & 1) ? $b : $b << 8;
	};
	$keytag = 0xffff & ($crc + ($crc >> 16));
	$parts = explode(".", $domain);
	$domain_wire_format = '';
	foreach ($parts as $part) {
		$domain_wire_format .= pack('C',strlen($part)).$part;
	};
        return array($keytag, strtoupper(hash($digest_alg, $domain_wire_format . $dnskey_rdata)));
};

$dnskey = array(
	'domain' => 'example.com.',
	'flags' => '257',
	'protocol' => 3,
	'algorithm' => '13',
	'key' => "6a81escFb5QysOzJopVCPslEyldHJxOlNIq3ol0xZPeLn6HBLwdRIaxz1aYpefJHPaj+seBti4j5gLWYetY3vA==",
);

list($keytag, $digest) = calc_ds($dnskey['domain'], $dnskey['flags'], $dnskey['protocol'], $dnskey['algorithm'], $dnskey['key'],'sha1');
print($dnskey['domain'] ." IN DS $keytag " . $dnskey['protocol'] . " 1 $digest; test: 20545 13 1 40bd7cf025eeb433f9e74127009bd0af8c16f449\n");
list($keytag, $digest) = calc_ds($dnskey['domain'], $dnskey['flags'], $dnskey['protocol'], $dnskey['algorithm'], $dnskey['key'],'sha256');
print($dnskey['domain'] ." IN DS $keytag " . $dnskey['protocol'] . " 2 $digest; test: 20545 13 2 e460eab7d69abde51078bc27ce8377074ca94ee05f5a609e5593c5e25acf2bf4\n");
list($keytag, $digest) = calc_ds($dnskey['domain'], $dnskey['flags'], $dnskey['protocol'], $dnskey['algorithm'], $dnskey['key'],'gost-crypto');
print($dnskey['domain'] ." IN DS $keytag " . $dnskey['protocol'] . " 3 $digest; test: 20545 13 3 9b8e8392b2c8203cec672ae891329221678ce06e5fe861db61688f0c1ca0b494\n");
list($keytag, $digest) = calc_ds($dnskey['domain'], $dnskey['flags'], $dnskey['protocol'], $dnskey['algorithm'], $dnskey['key'],'sha384');
print($dnskey['domain'] ." IN DS $keytag " . $dnskey['protocol'] . " 4 $digest; test: 20545 13 4 99436f3fb883ca4f077798c206037d97a34560245e57f1ffb10222b12ab8bd73755b1c41bff6cf039e942cd3cb3950c1\n");
?>

