package jmdbtutorial.crypto;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

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

        Base64.Decoder decoder = Base64.getDecoder();

        byte[] signatureData = decoder.decode(signatureBase64.getBytes());
        byte[] publicKeyEncoded = decoder.decode(publicKeyEncodedBase64);

        KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyEncoded);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        Signature signature = Signature.getInstance("SHA1withDSA", "SUN");
        signature.initVerify(publicKey);

        BufferedInputStream in = new BufferedInputStream(dataUrl.openStream());
        byte[] buffer = new byte[1024];
        int len;
        while (in.available() != 0) {
            len = in.read(buffer);
            signature.update(buffer, 0, len);
        }

        in.close();

        return signature.verify(signatureData);

    }

    public static String encodeAsBase64(PublicKey aPublic) {
        return Base64.getEncoder().encodeToString(aPublic.getEncoded());
    }
}
