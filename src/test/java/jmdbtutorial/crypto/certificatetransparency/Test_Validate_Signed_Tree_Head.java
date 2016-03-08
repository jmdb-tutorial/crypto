package jmdbtutorial.crypto.certificatetransparency;

import jmdbtutorial.crypto.DataSigning;
import jmdbtutorial.crypto.Test_CryptoHashSigning;
import jmdbtutorial.crypto.Test_CryptoHashing;
import jmdbtutorial.platform.http.Http;
import jmdbtutorial.platform.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.junit.Test;
import sun.security.util.DerEncoder;
import sun.security.util.DerValue;

import java.nio.ByteBuffer;

import static java.lang.String.format;
import static java.lang.System.out;
import static jmdbtutorial.crypto.DataSigning.base64AsBytes;
import static jmdbtutorial.crypto.Test_CryptoHashing.printHexBytes;

/**
 * https://tools.ietf.org/html/rfc6962#section-4.3
 * https://tools.ietf.org/html/rfc5246#section-4.7
 * https://www.imperialviolet.org/2013/08/01/ctpilot.html
 * https://tools.ietf.org/html/draft-laurie-pki-sunlight-09#section-3.5
 *
 */
public class Test_Validate_Signed_Tree_Head {

    private static final byte LOG_VERSION = 0;
    private static final byte TREE_HASH = 1;

    private Http http = new Http().init();



    /**
       digitally-signed struct {
           Version version;
           SignatureType signature_type = tree_hash;
           uint64 timestamp;
           uint64 tree_size;
           opaque sha256_root_hash[32];
       } TreeHeadSignature;

     https://tools.ietf.org/html/rfc5246#section-4.7
     Signature is in DSA form. which looks like this:

     Dss-Sig-Value ::= SEQUENCE {
        r INTEGER,
        s INTEGER
     }
     from https://tools.ietf.org/html/rfc5246#section-4.7

     This is encoded in DER encoding (https://en.wikipedia.org/wiki/X.690#DER_encoding)

     https://tools.ietf.org/html/rfc6962#section-4.3
     The hash is encoded in base64
     */
    @Test
    public void validateSignedTreeHead() {

        HttpGet get = new HttpGet("http://ct.googleapis.com/pilot/ct/v1/get-sth");

        HttpResponse response = http.execute(get);

        SignedTreeHeadResponse sthResponse = SignedTreeHeadResponse.parse(response);

        out.println(sthResponse.toString());

        // see https://tools.ietf.org/html/draft-laurie-pki-sunlight-09#section-3.5

        byte[] hashBytes = base64AsBytes(sthResponse.sha256_root_hash);
        out.println("Hash length (bytes) : " + hashBytes.length);

        ByteBuffer buf = ByteBuffer.allocate(2+8+8+32);

        buf.put(LOG_VERSION);
        buf.put(TREE_HASH);
        buf.putLong(sthResponse.timestamp); // writes 8 byte version of the long
        buf.putLong(sthResponse.tree_size);

        buf.put(hashBytes);

        byte[] bytesToVerify = buf.array();

        out.println("Bytes to verify length : " + bytesToVerify.length);
        out.println("Bytes (hex)            :" + printHexBytes(bytesToVerify, 1));

    }

    private byte[] parseBytesFromDERString(String tree_head_signature) throws Exception {
        DerValue val = new DerValue(tree_head_signature);

        return val.getDataBytes();
    }

    private static class SignedTreeHeadResponse {
        public final int tree_size;
        public final long timestamp;
        public final String sha256_root_hash;
        public final String tree_head_signature;

        public static SignedTreeHeadResponse parse(HttpResponse response) {
            return new SignedTreeHeadResponse(
                    response.intValue("tree_size"),
                    response.longValue("timestamp"),
                    response.stringValue("sha256_root_hash"),
                    response.stringValue("tree_head_signature")
                );

        }

        public SignedTreeHeadResponse(int tree_size,
                                      long timestamp,
                                      String sha256_root_hash,
                                      String tree_head_signature) {
            this.tree_size = tree_size;
            this.timestamp = timestamp;
            this.sha256_root_hash = sha256_root_hash;
            this.tree_head_signature = tree_head_signature;
        }

        public String toString() {

            return new StringBuilder()
                    .append(format("tree_size           : %d%n", tree_size))
                    .append(format("timestamp           : %d%n", timestamp))
                    .append(format("sha256_root_hash    : %s%n", sha256_root_hash))
                    .append(format("tree_head_signature : %s%n", tree_head_signature))
                    .toString();

        }
    }
}
