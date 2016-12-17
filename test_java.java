import java.io.*;
import java.security.Security;

// DNS library http://www.dnsjava.org/
import org.xbill.DNS.utils.base64;
import org.xbill.DNS.Name;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DSRecord;

// external cryptoprovider BouncyCastle http://www.bouncycastle.org/
// for GOST 34.11-94 hash
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.provider.digest.GOST3411;

class TestCalcDS {
        public static void main(String[] args) {
                // use external cryptoprovider
                Security.addProvider(new BouncyCastleProvider());
                // create domain object with test domain name
                Name owner = Name.fromConstantString("example.com.");
                // create DNSKEY object with test data
                DNSKEYRecord dnskey = new DNSKEYRecord(owner, 1, 3600, 257, 3, 13, base64.fromString("6a81escFb5QysOzJopVCPslEyldHJxOlNIq3ol0xZPeLn6HBLwdRIaxz1aYpefJHPaj+seBti4j5gLWYetY3vA=="));
                // create DS objects
                DSRecord ds_sha256 = new DSRecord(owner, 1, 3600, 2, dnskey);
                DSRecord ds_gost3411 = new DSRecord(owner, 1, 3600, 3, dnskey);
                DSRecord ds_sha384 = new DSRecord(owner, 1, 3600, 4, dnskey);
                // output results with test test and calculated data
                System.out.println("REF:\texample.com.\t\t3600\tIN\tDS\t20545 13 2 E460EAB7D69ABDE51078BC27CE8377074CA94EE05F5A609E5593C5E25ACF2BF4");
                System.out.println("CALC:\t" + ds_sha256.toString() + "\n");
                System.out.println("REF:\texample.com.\t\t3600\tIN\tDS\t20545 13 3 9B8E8392B2C8203CEC672AE891329221678CE06E5FE861DB61688F0C1CA0B494");
                System.out.println("CALC:\t" + ds_gost3411.toString() + "\n");
                System.out.println("REF:\texample.com.\t\t3600\tIN\tDS\t20545 13 4 99436F3FB883CA4F077798C206037D97A34560245E57F1FFB10222B12AB8BD73755B1C41BFF6CF039E942CD3CB3950C1");
                System.out.println("CALC:\t" + ds_sha384.toString() + "\n");
        }
}

