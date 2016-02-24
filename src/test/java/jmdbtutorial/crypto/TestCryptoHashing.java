package jmdbtutorial.crypto;

import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.Base64;

import static java.lang.System.out;

public class TestCryptoHashing {

    @Test
    public void sha256_hash() throws Exception {
        String input = "This is a string that we want to hash";


        ByteArrayInputStream dataInputStream = new ByteArrayInputStream(input.getBytes("UTF-8"));

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");


        DigestInputStream in = new DigestInputStream(dataInputStream, messageDigest);

        byte[] buffer = new byte[8192];
        while (in.read(buffer) != -1) ;

        byte[] raw = messageDigest.digest();


        out.println("Digest Length : " + messageDigest.getDigestLength());
        out.println("Algorithm     : " + messageDigest.getAlgorithm());


        String base64Hash = new String(Base64.getEncoder().encode(raw));

        out.println("base64        : " + base64Hash);

        String hex = DatatypeConverter.printHexBinary(raw).toLowerCase();
        out.println("hex           : " + hex);

    }
}
