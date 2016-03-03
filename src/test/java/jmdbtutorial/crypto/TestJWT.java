package jmdbtutorial.crypto;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import org.junit.Test;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

import static java.lang.System.out;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class TestJWT {

    @Test
    public void create_and_validate_token() {
        SecureRandom random = new SecureRandom();

        Key key = MacProvider.generateKey(SignatureAlgorithm.HS256, random);

        byte[] rawKeyBytes = key.getEncoded();

        out.println("Key format       : " + key.getFormat());
        out.println("Secret (Hex)     : " + TestCryptoHashing.printHexBytes(rawKeyBytes, 0));
        out.println("Secret (Base64)  : " + Base64.getEncoder().encodeToString(key.getEncoded()));

        String s = Jwts.builder()
                .setSubject("Joe")
                .signWith(SignatureAlgorithm.HS256, key)
                .compact();

        out.println("JWT              : " + s);
        out.println("Validate it here : http://jwt.io/#debugger");

        boolean subjectMatches = Jwts.parser()
                .setSigningKey(key)
                .parseClaimsJws(s)
                .getBody().getSubject().equals("Joe");


        assertThat(subjectMatches, is(true));
    }

}
