package main

import (
        "encoding/base64"
        "strings"
        "bytes"
        "hash"
        "crypto/sha1"
        "crypto/sha256"
        "cypherpunks.ru/gogost/gost28147"       // http://www.cypherpunks.ru/gogost/ >=2.0
        "cypherpunks.ru/gogost/gost341194"      // for GOST 34.11-94 hash
        "crypto/sha512"
        "encoding/hex"
        "fmt"
       )

const (
        SHA1 = iota
        SHA256
        GOST_CRYPTO
        SHA384
      )

// domain        - string, the canonical domain name with trailing dot
// flags         - uint16 flags, the flags of the DNSKEY (always 257)
// protocol      - uint8 protocol, the protocol of the DNSKEY (always 3)
// algorithm     - uint8 algoritm, the algorithm of the DNSKEY (5, 7, 8, 10, 12, 13 or 14)
// publickey     - string publickey, the full publickey base64 encoded (care, no spaces allowed)
// digest_alg    - int, the hash algorithm for the DS digest (constants SHA1, SHA256, GOST_CRYPTO or SHA384)
//
// return keytag and DS signature as a array
func calc_ds(owner string, flags uint16, protocol uint8, algorithm uint8, publickey string, digest_alg int) (uint16,[]byte) {
        var keytag uint32
        // pack DNSKEY RDATA to wire format
        dnskey_rdata := []byte{byte(flags >> 8), byte(flags), byte(protocol), byte(algorithm)}
        decoded_publickey, _ := base64.StdEncoding.DecodeString(publickey)
        dnskey_rdata = append(dnskey_rdata, decoded_publickey...)
        // calculate keytag
        for i, b := range dnskey_rdata {
                if i&1 != 0 {
                        keytag += uint32(b)
                } else {
                        keytag += uint32(b) << 8
                }
        }
        keytag = ((keytag & 0xFFFF) + ((keytag >> 16) & 0xFFFF)) & 0xFFFF
        // pack owner name to wire format
        domain_wire_format := make([]byte, 0, 256)
        for _, part := range strings.Split(owner, ".") {
                domain_wire_format = append(domain_wire_format, byte(len(part)))
                domain_wire_format = append(domain_wire_format, part[:]...)
        }
        // calculate digest
        var hasher hash.Hash
	switch digest_alg {
	case SHA1:
		hasher = sha1.New()
	case SHA256:
		hasher = sha256.New()
        case GOST_CRYPTO:
                hasher = gost341194.New(&gost28147.GostR3411_94_CryptoProParamSet)
	case SHA384:
		hasher = sha512.New384()
	}
        hasher.Write(append(domain_wire_format, dnskey_rdata[:]...))
        digest := make([]byte, 2 * hasher.Size())
        hex.Encode(digest, hasher.Sum(nil))
        return uint16(keytag), bytes.ToUpper(digest)
}

// Проверка на тестовых данных
func main() {
        type Dnskey struct {
                domain string
                flags uint16
                protocol uint8
                algorithm  uint8
                publickey string
        }
        var keytag uint16
        var digest []byte
        d := Dnskey{"example.com.", 257, 3, 13, "6a81escFb5QysOzJopVCPslEyldHJxOlNIq3ol0xZPeLn6HBLwdRIaxz1aYpefJHPaj+seBti4j5gLWYetY3vA=="}
        keytag, digest = calc_ds(d.domain, d.flags, d.protocol, d.algorithm, d.publickey, SHA1)
        fmt.Println("REF:    example.com. IN DS 20545 13 1 40BD7CF025EEB433F9E74127009BD0AF8C16F449")
        fmt.Printf("CALC:   %s IN DS %d %d 1 %s\n\n", d.domain, keytag, d.algorithm, digest)
        keytag, digest = calc_ds(d.domain, d.flags, d.protocol, d.algorithm, d.publickey, SHA256)
        fmt.Println("REF:    example.com. IN DS 20545 13 2 E460EAB7D69ABDE51078BC27CE8377074CA94EE05F5A609E5593C5E25ACF2BF4")
        fmt.Printf("CALC:   %s IN DS %d %d 2 %s\n\n", d.domain, keytag, d.algorithm, digest)
        keytag, digest = calc_ds(d.domain, d.flags, d.protocol, d.algorithm, d.publickey, GOST_CRYPTO)
        fmt.Println("REF:    example.com. IN DS 20545 13 3 9B8E8392B2C8203CEC672AE891329221678CE06E5FE861DB61688F0C1CA0B494")
        fmt.Printf("CACL:   %s IN DS %d %d 3 %s\n\n", d.domain, keytag, d.algorithm, digest)
        keytag, digest = calc_ds(d.domain, d.flags, d.protocol, d.algorithm, d.publickey, SHA384)
        fmt.Println("REF:    example.com. IN DS 20545 13 4 99436F3FB883CA4F077798C206037D97A34560245E57F1FFB10222B12AB8BD73755B1C41BFF6CF039E942CD3CB3950C1")
        fmt.Printf("CALC:   %s IN DS %d %d 4 %s\n", d.domain, keytag, d.algorithm, digest)
}

