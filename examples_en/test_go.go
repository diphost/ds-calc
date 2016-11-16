package main

import (
        "encoding/base64"
        "strings"
        "hash"
        "crypto/sha1"
        "crypto/sha256"
        "cypherpunks.ru/gogost/gost28147"       // http://www.cypherpunks.ru/gogost/
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
// flags         - uint16 flags, the flags of the DNSKEY (only 257)
// protocol      - uint8 protocol, the protocol of the DNSKEY (only 3)
// algorithm     - uint8 algoritm, the algorithm of the DNSKEY (only 3, 5, 6, 7, 8, 10, 12, 13 or 14)
// publickey     - string publickey, the full publickey base64 encoded (care, no spaces allowed)
// digest_alg    - int, the hash algorithm for the DS digest (constants SHA1, SHA256, GOST_CRYPTO or SHA384)
//
// return keytag and DS signature as a array

func calc_ds(owner string, flags uint16, protocol uint8, algorithm uint8, publickey string, digest_alg int) (uint16,[]byte) {
        var keytag int
        dnskey_rdata := []byte{byte(flags >> 8), byte(flags), byte(protocol), byte(algorithm)}
        decoded_publickey, _ := base64.StdEncoding.DecodeString(publickey)
        dnskey_rdata = append(dnskey_rdata, decoded_publickey...)
        for i, b := range dnskey_rdata {
                if i&1 != 0 {
                        keytag += int(b)
                } else {
                        keytag += int(b) << 8
                }
        }
        keytag += (keytag >> 16) & 0xFFFF
        keytag &= 0xFFFF
        domain_wire_format := make([]byte, 0, 256)
        for _, part := range strings.Split(owner, ".") {
                domain_wire_format = append(domain_wire_format, byte(len(part)))
                domain_wire_format = append(domain_wire_format, part[:]...)
        }
	var digest, digest_bin []byte
        var hasher hash.Hash
        var size int
	switch digest_alg {
	case SHA1:
		hasher = sha1.New()
                size = sha1.Size
                hasher.Write(append(domain_wire_format, dnskey_rdata[:]...))
                digest_bin = make([]byte, size)
                digest_bin = hasher.Sum(nil)
	case SHA256:
		hasher = sha256.New()
                size = sha256.Size
                hasher.Write(append(domain_wire_format, dnskey_rdata[:]...))
                digest_bin = make([]byte, size)
                digest_bin = hasher.Sum(nil)
        case GOST_CRYPTO:
                hasher = gost341194.New(&gost28147.GostR3411_94_CryptoProParamSet)
                size = hasher.Size()
                hasher.Write(append(domain_wire_format, dnskey_rdata[:]...))
                digest_bin = make([]byte, size)
                digest_bin = hasher.Sum(nil)
                for i, j := 0, len(digest_bin)-1; i < j; i, j = i+1, j-1 {
                        digest_bin[i], digest_bin[j] = digest_bin[j], digest_bin[i]
                }
	case SHA384:
		hasher = sha512.New384()
                size = sha512.Size384
                digest_bin = hasher.Sum(nil)
	}
        digest = make([]byte, size*2)
        hex.Encode(digest, digest_bin)
        return uint16(keytag), digest
}

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
        fmt.Println("Reference: 20545 40bd7cf025eeb433f9e74127009bd0af8c16f449")
        fmt.Printf("Keytag:    %d %s\n", keytag, digest)
        keytag, digest = calc_ds(d.domain, d.flags, d.protocol, d.algorithm, d.publickey, SHA256)
        fmt.Println("Reference: 20545 e460eab7d69abde51078bc27ce8377074ca94ee05f5a609e5593c5e25acf2bf4")
        fmt.Printf("Keytag:    %d %s\n", keytag, digest)
        keytag, digest = calc_ds(d.domain, d.flags, d.protocol, d.algorithm, d.publickey, GOST_CRYPTO)
        fmt.Println("Reference: 20545 9b8e8392b2c8203cec672ae891329221678ce06e5fe861db61688f0c1ca0b494")
        fmt.Printf("Keytag:    %d %s\n", keytag, digest)
        keytag, digest = calc_ds(d.domain, d.flags, d.protocol, d.algorithm, d.publickey, SHA384)
        fmt.Println("Reference: 20545 99436f3fb883ca4f077798c206037d97a34560245e57f1ffb10222b12ab8bd73755b1c41bff6cf039e942cd3cb3950c1")
        fmt.Printf("Keytag:    %d %s\n", keytag, digest)
}

