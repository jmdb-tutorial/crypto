package jmdbtutorial.crypto;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * https://en.wikipedia.org/wiki/Digital_signature
 *
 */
public class DataSigning {
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);

        return keyGen.generateKeyPair();
    }

    public static String signData(URL dataUrl, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, SignatureException {

        try (BufferedInputStream in = new BufferedInputStream(dataUrl.openStream())) {
            return signInputStream(in, privateKey);
        }
    }

    public static String signData(String data, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, SignatureException {

        try (BufferedInputStream in = new BufferedInputStream(new ByteArrayInputStream(data.getBytes()))) {
            return signInputStream(in, privateKey);
        }
    }

    private static String signInputStream(InputStream in, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, SignatureException {
        Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
        dsa.initSign(privateKey);

        byte[] buffer = new byte[1024];
        int len;
        while ((len = in.read(buffer)) >= 0) {
            dsa.update(buffer, 0, len);
        }


        byte[] signatureBytes = dsa.sign();
        return new String(Base64.getEncoder().encode(signatureBytes));
    }

    public static boolean verifyData(String publicKeyEncodedBase64, String signatureBase64, URL dataUrl) throws Exception {

        try (BufferedInputStream in = new BufferedInputStream(dataUrl.openStream())) {
            return verifyInputStream(publicKeyEncodedBase64, signatureBase64, in);
        }

    }

    public static boolean verifyData(String publicKeyEncodedBase64, String signatureBase64, String data) throws Exception {
        try (BufferedInputStream in = new BufferedInputStream(new ByteArrayInputStream(data.getBytes()))) {
            return verifyInputStream(publicKeyEncodedBase64, signatureBase64, in);
        }

    }

    private static boolean verifyInputStream(String publicKeyEncodedBase64, String signatureBase64, BufferedInputStream in) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, IOException, SignatureException {
        Base64.Decoder decoder = Base64.getDecoder();

        byte[] signatureData = decoder.decode(signatureBase64.getBytes());
        byte[] publicKeyEncoded = decoder.decode(publicKeyEncodedBase64);

        KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyEncoded);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        Signature signature = Signature.getInstance("SHA1withDSA", "SUN");
        signature.initVerify(publicKey);

        byte[] buffer = new byte[1024];
        int len;
        while (in.available() != 0) {
            len = in.read(buffer);
            signature.update(buffer, 0, len);
        }
        return signature.verify(signatureData);
    }

    public static String encodeAsBase64(PublicKey aPublic) {
        return Base64.getEncoder().encodeToString(aPublic.getEncoded());
    }

    public static byte[] base64AsBytes(String sha256_root_hash)  {
        return Base64.getDecoder().decode(sha256_root_hash);
    }

    public static byte[] sha256Hash(byte[] input) throws Exception {
        ByteArrayInputStream dataInputStream = new ByteArrayInputStream(input);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");


        DigestInputStream in = new DigestInputStream(dataInputStream, messageDigest);

        byte[] buffer = new byte[8192];
        while (in.read(buffer) != -1) ;

        return messageDigest.digest();

    }


}
