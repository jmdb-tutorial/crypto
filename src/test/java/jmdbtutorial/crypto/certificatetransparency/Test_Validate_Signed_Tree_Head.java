package jmdbtutorial.crypto.certificatetransparency;

import jmdbtutorial.crypto.Test_CryptoHashing;
import jmdbtutorial.platform.http.Http;
import jmdbtutorial.platform.http.HttpResponse;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.methods.HttpGet;
import org.junit.Test;
import sun.security.util.DerValue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static java.lang.String.format;
import static java.lang.System.out;
import static jmdbtutorial.crypto.DataSigning.base64AsBytes;
import static jmdbtutorial.crypto.DataSigning.sha256Hash;
import static jmdbtutorial.crypto.Test_CryptoHashing.printHexBytes;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;

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

    private static String PILOT_LOG_PUBLICK_KEY_PEM = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==";



    private Http http = new Http().init();


    @Test
    public void load_public_key() throws Exception {
        PublicKey key = parsePublicKeyFromString(PILOT_LOG_PUBLICK_KEY_PEM);

        out.println(key);
    }

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

     // see https://tools.ietf.org/html/draft-laurie-pki-sunlight-09#section-3.5

     */
    @Test
    public void validateSignedTreeHead() throws Exception {

        HttpGet get = new HttpGet("http://ct.googleapis.com/pilot/ct/v1/get-sth");

        HttpResponse response = http.execute(get);

        SignedTreeHeadResponse sthResponse = SignedTreeHeadResponse.parse(response);

        out.println(sthResponse.toString());



        ByteBuffer buf = ByteBuffer.allocate(2+8+8+32);

        buf.put(LOG_VERSION);
        buf.put(TREE_HASH);
        buf.putLong(sthResponse.timestamp); // writes 8 byte version of the long
        buf.putLong(sthResponse.tree_size);

        byte[] hashBytes = base64AsBytes(sthResponse.sha256_root_hash);
        out.println("Hash length (bytes)    : " + hashBytes.length);
        buf.put(hashBytes);

        byte[] bytesToVerify = buf.array();

        out.println("Bytes to verify length : " + bytesToVerify.length);
        out.println("Bytes (hex)            :" + printHexBytes(bytesToVerify, 1));

        byte[] sha256DigestToVerify = sha256Hash(bytesToVerify);

        PublicKey logPublicKey = parsePublicKeyFromString(PILOT_LOG_PUBLICK_KEY_PEM);




        ByteArrayInputStream in = new ByteArrayInputStream(sha256DigestToVerify);

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(logPublicKey);

        byte[] buffer = new byte[1024];
        int len;
        while (in.available() != 0) {
            len = in.read(buffer);
            signature.update(buffer, 0, len);
        }
        byte[] digitallySignedBytes = base64AsBytes(sthResponse.tree_head_signature);

        out.println("digitallySignedBytes :" + printHexBytes(digitallySignedBytes, 1));

        // See https://tools.ietf.org/html/rfc5246#section-4.7
        byte hashFunctionByte = digitallySignedBytes[0];
        byte algorithmByte = digitallySignedBytes[1];
        out.println("Hash function byte : " + hashFunctionByte);
        out.println("Algorithm byte     : " + algorithmByte);


        byte[] signatureBytesDerEncoded = Arrays.copyOfRange(digitallySignedBytes, 2, digitallySignedBytes.length);

        byte[] rawSignature = parseBytesFromDER(signatureBytesDerEncoded);

        out.println("Raw signature      :" + printHexBytes(rawSignature, 1));
        boolean isValid =  signature.verify(rawSignature);

        out.println("Is Valid : " + isValid);


    }

    private byte[] parseBytesFromDER(byte[] input) throws Exception {
        DerValue val = new DerValue(input);

        return val.getDataBytes();
    }

    /**
     * From http://stackoverflow.com/a/27621696
     * @param publicKey
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static PublicKey parsePublicKeyFromString(String publicKey) throws IOException, GeneralSecurityException {
        java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();

        byte[] publicKeyBytes = decoder.decode(publicKey);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

        return keyFactory.generatePublic(publicKeySpec);

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
