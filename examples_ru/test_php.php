<?php

/*
 * $domain      - string, каноническое имя домена с точкой на конце
 * $flags       - int, флаги DNSKEY (для KSK всегда 257)
 * $protocol    - int, протокол DNSKEY (всегда 3)
 * $algorithm   - int, алгоритм ключа DNSKEY (5, 7, 8, 10, 12, 13 или 14)
 * $publickey   - string, публичная часть ключа DNSKEY в base64 кодировке (без пробелов)
 * $digest_alg  - string, алгоритм отпечатка для DS (sha1, sha256, gost-crypto или sha384)
 *
 * возвращает массив, состоящий из keytag и отпечатка DS
 *
 * Внимание: хэф-функция gost-crypto требует php версии 5.6 и выше
*/
function calc_ds($domain, $flags, $protocol, $algorithm, $publickey, $digest_alg) {
        # сформировать бинарную DNSKEY RDATA
	$dnskey_rdata = pack('nCC', intval($flags), intval($protocol), intval($algorithm));
	$dnskey_rdata .= base64_decode($publickey);
        # вычислить контрольную сумму keytag
	$crc = 0;
	for($i = 0; $i < strlen($dnskey_rdata); $i++) {
		$b = ord($dnskey_rdata[$i]);
		$crc += ($i & 1) ? $b : $b << 8;
	};
	$keytag = 0xffff & ($crc + ($crc >> 16));
        # сформировать бинарный вид доменного имени
	$parts = explode(".", $domain);
	$domain_wire_format = '';
	foreach ($parts as $part) {
		$domain_wire_format .= pack('C',strlen($part)).$part;
	};
        # создать отпечаток требуемого типа
        return array($keytag, strtoupper(hash($digest_alg, $domain_wire_format . $dnskey_rdata)));
};

# Проверка на тестовых данных
$dnskey = array(
	'domain' => 'example.com.',
	'flags' => '257',
	'protocol' => 3,
	'algorithm' => '13',
	'key' => "6a81escFb5QysOzJopVCPslEyldHJxOlNIq3ol0xZPeLn6HBLwdRIaxz1aYpefJHPaj+seBti4j5gLWYetY3vA==",
);

list($keytag, $digest) = calc_ds($dnskey['domain'], $dnskey['flags'], $dnskey['protocol'], $dnskey['algorithm'], $dnskey['key'],'sha1');
print("ЭТАЛОН:    example.com. IN DS 20545 13 1 40BD7CF025EEB433F9E74127009BD0AF8C16F449\n");
print("ВЫЧИСЛЕНО: " . $dnskey['domain'] ." IN DS $keytag ". $dnskey['algorithm'] . " 1 $digest\n\n");
list($keytag, $digest) = calc_ds($dnskey['domain'], $dnskey['flags'], $dnskey['protocol'], $dnskey['algorithm'], $dnskey['key'],'sha256');
print("ЭТАЛОН:    example.com. IN DS 20545 13 2 E460EAB7D69ABDE51078BC27CE8377074CA94EE05F5A609E5593C5E25ACF2BF4\n");
print("ВЫЧИСЛЕНО: " . $dnskey['domain'] ." IN DS $keytag ". $dnskey['algorithm'] . " 2 $digest\n\n");
list($keytag, $digest) = calc_ds($dnskey['domain'], $dnskey['flags'], $dnskey['protocol'], $dnskey['algorithm'], $dnskey['key'],'gost-crypto');
print("ЭТАЛОН:    example.com. IN DS 20545 13 3 9B8E8392B2C8203CEC672AE891329221678CE06E5FE861DB61688F0C1CA0B494\n");
print("ВЫЧИСЛЕНО: " . $dnskey['domain'] ." IN DS $keytag ". $dnskey['algorithm'] . " 3 $digest\n\n");
list($keytag, $digest) = calc_ds($dnskey['domain'], $dnskey['flags'], $dnskey['protocol'], $dnskey['algorithm'], $dnskey['key'],'sha384');
print("ЭТАЛОН:    example.com. IN DS 20545 13 4 99436F3FB883CA4F077798C206037D97A34560245E57F1FFB10222B12AB8BD73755B1C41BFF6CF039E942CD3CB3950C1\n");
print("ВЫЧИСЛЕНО: " . $dnskey['domain'] ." IN DS $keytag ". $dnskey['algorithm'] . " 4 $digest\n");
?>

