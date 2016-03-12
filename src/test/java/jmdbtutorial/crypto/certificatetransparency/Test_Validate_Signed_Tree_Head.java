package jmdbtutorial.crypto.certificatetransparency;

import jmdbtutorial.platform.http.Http;
import jmdbtutorial.platform.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.junit.Test;
import sun.security.util.DerValue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Enumeration;

import static java.lang.String.format;
import static java.lang.System.out;
import static jmdbtutorial.crypto.DataSigning.base64AsBytes;
import static jmdbtutorial.crypto.DataSigning.sha256Hash;
import static jmdbtutorial.crypto.Test_CryptoHashing.printHexBytes;
import static jmdbtutorial.crypto.Test_CryptoHashing.printUnsignedBytes;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

/**
 * https://tools.ietf.org/html/rfc6962#section-4.3
 * https://tools.ietf.org/html/rfc5246#section-4.7
 * https://www.imperialviolet.org/2013/08/01/ctpilot.html
 * https://tools.ietf.org/html/draft-laurie-pki-sunlight-09#section-3.5
 * https://www.bouncycastle.org/wiki/display/JA1/Elliptic+Curve+Key+Pair+Generation+and+Key+Factories#EllipticCurveKeyPairGenerationandKeyFactories-WithNamedCurves.2
 */
public class Test_Validate_Signed_Tree_Head {

    private static final byte LOG_VERSION = 0;
    private static final byte TREE_HASH = 1;

    public static final int MAX_SIGNATURE_LENGTH = (1 << 16) - 1; // From org.certificatetransparency.ctlog.serialization.Deserializer

    private static String PILOT_LOG_PUBLICK_KEY_PEM = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==";


    private Http http = new Http().init();


    @Test
    public void load_public_key() throws Exception {
        PublicKey key = parsePublicKeyFromString(PILOT_LOG_PUBLICK_KEY_PEM);

        out.println(key);


    }


    @Test
    public void available_curves_bc() {
        out.println("Available curves:");
        Enumeration names = ECNamedCurveTable.getNames();
        while (names.hasMoreElements()) {
            out.println(names.nextElement());
        }
    }

    @Test
    public void load_public_key_bc() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String pilotLogPublickKeyPem = PILOT_LOG_PUBLICK_KEY_PEM;
        Security.addProvider(new BouncyCastleProvider());

        PublicKey publicKey = loadPublicKeyViaBc(pilotLogPublickKeyPem);

        out.println("Public Key : " + publicKey);

    }


    /**
     * digitally-signed struct {
     * Version version;
     * SignatureType signature_type = tree_hash;
     * uint64 timestamp;
     * uint64 tree_size;
     * opaque sha256_root_hash[32];
     * } TreeHeadSignature;
     * <p>
     * https://tools.ietf.org/html/rfc5246#section-4.7
     * Signature is in DSA form. which looks like this:
     * <p>
     * Dss-Sig-Value ::= SEQUENCE {
     * r INTEGER,
     * s INTEGER
     * }
     * from https://tools.ietf.org/html/rfc5246#section-4.7
     * <p>
     * This is encoded in DER encoding (https://en.wikipedia.org/wiki/X.690#DER_encoding)
     * <p>
     * https://tools.ietf.org/html/rfc6962#section-4.3
     * The hash is encoded in base64
     * <p>
     * // see https://tools.ietf.org/html/draft-laurie-pki-sunlight-09#section-3.5
     */
    @Test
    public void validateSignedTreeHead() throws Exception {

        HttpGet get = new HttpGet("http://ct.googleapis.com/pilot/ct/v1/get-sth");

        HttpResponse response = http.execute(get);

        SignedTreeHeadResponse sthResponse = SignedTreeHeadResponse.parse(response);

        out.println(sthResponse.toString());


        ByteBuffer buf = ByteBuffer.allocate(2 + 8 + 8 + 32);

        buf.put(LOG_VERSION);
        buf.put(TREE_HASH);
        buf.putLong(sthResponse.timestamp); // writes 8 byte version of the long
        buf.putLong(sthResponse.tree_size);

        byte[] hashBytes = base64AsBytes(sthResponse.sha256_root_hash);
        out.println("Hash length (bytes)      : " + hashBytes.length);
        buf.put(hashBytes);

        byte[] bytesToVerify = buf.array();

        out.println("Bytes to verify length   : " + bytesToVerify.length);
        out.println("Bytes (uint)             :" + printUnsignedBytes(bytesToVerify, 4));

        byte[] sha256DigestToVerify = sha256Hash(bytesToVerify);

        out.println("Hash to verify (uint)    :" + printUnsignedBytes(sha256DigestToVerify, 4));
        out.println("Hash to verify (hex)     :" + printHexBytes(sha256DigestToVerify, 1));
        PublicKey logPublicKey = parsePublicKeyFromString(PILOT_LOG_PUBLICK_KEY_PEM);


        out.println("Public Key               :" + printUnsignedBytes(logPublicKey.getEncoded(), 4));

        byte[] treeHeadSignature = base64AsBytes(sthResponse.tree_head_signature);
        out.println("treeHeadSignature        :" + printUnsignedBytes(treeHeadSignature, 4));
        out.println("treeHeadSignature.length :  " + treeHeadSignature.length);

        // See https://tools.ietf.org/html/rfc5246#section-4.7
        byte hashFunctionByte = treeHeadSignature[0];
        byte algorithmByte = treeHeadSignature[1];
        out.println("Hash function byte       :   " + hashFunctionByte);
        out.println("Algorithm byte           :   " + algorithmByte);

        out.println("Max signature Length     :   " + MAX_SIGNATURE_LENGTH);
        out.println("Number of bytes required :   " + bytesForDataLength(MAX_SIGNATURE_LENGTH));

        int length = ((treeHeadSignature[2] & 0xff) << 8) | (treeHeadSignature[3] & 0xff); // from http://stackoverflow.com/a/4768950 // @TODO - explore further demonstrating how to read bytes into an integer
        out.println("Signature.length (stated):  " + length);

        byte[] signatureBytesEncoded = Arrays.copyOfRange(treeHeadSignature, 4, treeHeadSignature.length); //http://luca.ntop.org/Teaching/Appunti/asn1.html
        out.println("Signature.length (actual):  " + signatureBytesEncoded.length);
        out.println("Signature                :" + printUnsignedBytes(signatureBytesEncoded, 4));


        byte[] rawSignature = parseBytesFromDER(signatureBytesEncoded);
        out.println("Raw signature            :" + printUnsignedBytes(rawSignature, 4));
        out.println("Raw signature.length     :  " + rawSignature.length);


        //boolean isValid = verifySignatureDirectBc(sha256DigestToVerify, signatureBytesEncoded);
        //boolean isValid = verifyUsingJCE_BC(bytesToVerify, signatureBytesEncoded);

        boolean isValid = verifyUsingJCE(bytesToVerify, signatureBytesEncoded);

        out.println("Is Valid : " + isValid);


        assertThat(isValid, is(true));
    }

    private static boolean verifyUsingJCE_BC(byte[] bytesToVerify, byte[] signatureBytesEncoded) throws GeneralSecurityException, IOException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        out.println("Has Provider : " + provider.hasAlgorithm("Signature", "SHA256withECDSA"));

        debugRandSViaStandardDSAEncoder(signatureBytesEncoded);

        debugHash(bytesToVerify);

        java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();

        byte[] publicKeyBytes = decoder.decode(PILOT_LOG_PUBLICK_KEY_PEM);

        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC"); // Can use the sun one if you want, just don't put the "BC" param

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        out.println("Public Key    : " + publicKey);

        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(bytesToVerify);// Note we don't pass the HASH in here it does it for us!

        return ecdsaVerify.verify(signatureBytesEncoded);
    }

    private static boolean verifyUsingJCE(byte[] bytesToVerify, byte[] signatureBytesEncoded) throws GeneralSecurityException, IOException {


        java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();

        byte[] publicKeyBytes = decoder.decode(PILOT_LOG_PUBLICK_KEY_PEM);

        KeyFactory keyFactory = KeyFactory.getInstance("EC"); // Can use the sun one if you want, just don't put the "BC" param

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        out.println("Public Key    : " + publicKey);

        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(bytesToVerify);// Note we don't pass the HASH in here it does it for us!

        return ecdsaVerify.verify(signatureBytesEncoded);
    }

    /**
     * From DSABase.engineVerify
     */
    private static void debugHash(byte[] sha256DigestToVerify) {

        SHA256Digest digest = new SHA256Digest();
        digest.update(sha256DigestToVerify, 0, sha256DigestToVerify.length);
        byte[]  hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        out.println("Hash                  " + digest.toString());
        out.println("Hash to verify (uint) " + printUnsignedBytes(hash, 4));


    }

    private boolean verifySignatureDirectBc(byte[] sha256DigestToVerify, byte[] signatureBytesEncoded) throws IOException {
        ASN1StreamParser parser = new ASN1StreamParser(signatureBytesEncoded);
        ASN1Encodable asn1Encodable = parser.readObject();

        DERSequence derSequence = (DERSequence) asn1Encodable.toASN1Primitive();

        out.println("DER sequence           : " + derSequence);

        ASN1Integer R = (ASN1Integer) derSequence.getObjectAt(0);
        ASN1Integer S = (ASN1Integer) derSequence.getObjectAt(1);

        out.println("R                      : " + R);
        out.println("S                      : " + S);




        ECDSASigner ecdsa = new ECDSASigner();

        java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();

        byte[] publicKeyBytes = decoder.decode(PILOT_LOG_PUBLICK_KEY_PEM);

        ECPublicKeyParameters bpubKey = (ECPublicKeyParameters) PublicKeyFactory.createKey(publicKeyBytes);
        out.println("Public key params from EC     : " + bpubKey.getParameters());
        out.println("Public key Q                  : " + bpubKey.getQ());


        ecdsa.init(false, bpubKey);

        return ecdsa.verifySignature(sha256DigestToVerify, R.getValue(), S.getValue());
    }

    /**
     * Taken from StdDSAEncoder in SignatureSpi in bouncy castle
     */
    private static void debugRandSViaStandardDSAEncoder(byte[] signatureBytesEncoded) throws IOException {
        ASN1Sequence s = (ASN1Sequence)ASN1Primitive.fromByteArray(signatureBytesEncoded);
        BigInteger[] sig = new BigInteger[2];

        sig[0] = ASN1Integer.getInstance(s.getObjectAt(0)).getValue();
        sig[1] = ASN1Integer.getInstance(s.getObjectAt(1)).getValue();

        out.println("From StdDSAEncoder");

        out.println("R                      : " + sig[0]);
        out.println("S                      : " + sig[1]);
    }

    /**
     * From org.certificatetransparency.ctlog.serialization.Deserializer
     */
    public static int bytesForDataLength(int maxDataLength) {
        return (int) (Math.ceil(Math.log(maxDataLength) / Math.log(2)) / 8);
    }


    private byte[] parseBytesFromDER(byte[] input) throws Exception {
        DerValue val = new DerValue(input);

        return val.getDataBytes();
    }

    /**
     * From http://stackoverflow.com/a/27621696
     *
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

    private static PublicKey loadPublicKeyViaBc(String pilotLogPublickKeyPem) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();


        byte[] publicKeyBytes = decoder.decode(pilotLogPublickKeyPem);

        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("P-256"); // secp256k1
        ECCurve curve = params.getCurve();

        java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, params.getSeed());

        out.println("Curve : " + ellipticCurve.getField());
        out.println("Public Key: " + printHexBytes(publicKeyBytes, 1));
        out.println("Public Key length : " + publicKeyBytes.length);

        SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(publicKeyBytes));

        out.println("Algorithmg: " + pubKeyInfo.getAlgorithm());

        // From https://bitcointalk.org/index.php?topic=2899.0

        java.security.spec.ECPoint point = ECPointUtil.decodePoint(ellipticCurve, pubKeyInfo.getPublicKeyData().getBytes());

        out.println("point.X : " + point.getAffineX());
        out.println("point.Y : " + point.getAffineY());

        java.security.spec.ECParameterSpec params2 = EC5Util.convertSpec(ellipticCurve, params);
        java.security.spec.ECPublicKeySpec keySpec = new java.security.spec.ECPublicKeySpec(point, params2);

        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        return keyFactory.generatePublic(keySpec);


    }

}
