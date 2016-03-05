package jmdbtutorial.crypto;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.util.Base64;

import static java.lang.System.out;
import static jmdbtutorial.crypto.DataSigning.generateKeyPair;
import static jmdbtutorial.crypto.DataSigning.signData;
import static jmdbtutorial.crypto.DataSigning.verifyData;
import static org.hamcrest.MatcherAssert.assertThat;

public class Test_CryptoHashSigning {

    @Test
    public void sign_and_validate_a_message() throws Exception {
        String message = "This is a message that only I can have sent";

        String messageHash = hash(message, "SHA-256").toString();

        out.println("Message hash : " + messageHash);

        KeyPair keyPair = generateKeyPair();

        String signature = signData(messageHash, keyPair.getPrivate());

        out.println("Signature    : " + signature);



    }



    public static Hash hash(String input, String algorithm) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);

        ByteArrayInputStream dataInputStream = new ByteArrayInputStream(input.getBytes("UTF-8"));


        DigestInputStream in = new DigestInputStream(dataInputStream, messageDigest);

        byte[] buffer = new byte[8192];
        while (in.read(buffer) != -1) ;


        return new Hash(messageDigest.digest());
    }

    private static class Hash {
        private final byte[] data;

        public Hash(byte[] data) {
            this.data = data;
        }

        public String toString() {
            return new String(Base64.getEncoder().encodeToString(data));
        }
    }
}
