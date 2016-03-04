package jmdbtutorial.crypto;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.crypto.MacProvider;
import org.junit.Test;

import java.security.Key;
import java.security.SecureRandom;
import java.util.*;

import static java.lang.System.out;
import static java.util.Arrays.asList;
import static java.util.stream.Collectors.joining;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

/**
 * https://tools.ietf.org/html/rfc7519
 * http://jwt.io/
 */
public class TestJWT {

    @Test
    public void create_and_validate_token() {
        SecureRandom random = new SecureRandom();

        Key key = MacProvider.generateKey(SignatureAlgorithm.HS256, random);

        byte[] rawKeyBytes = key.getEncoded();

        out.println("Key format       : " + key.getFormat());
        out.println("Secret (Hex)     : " + TestCryptoHashing.printHexBytes(rawKeyBytes, 0));
        out.println("Secret (Base64)  : " + Base64.getEncoder().encodeToString(key.getEncoded()));


        Claims roleBasedClaims = RoleBasedClaims.create("admin", "worker")
                .setSubject("Joe")
                .setAudience("destination.server.com")
                .setIssuer("source.server.com")
                .setIssuedAt(new Date());

        String s = Jwts.builder()
                .setClaims(roleBasedClaims)
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

    public static class RoleBasedClaims extends DefaultClaims {
        public static final String ROLES = "roles";


        public RoleBasedClaims() {
        }

        public static Claims create(String... roles) {
            return new RoleBasedClaims().setRoles(roles);
        }

        private Claims setRoles(String... roles) {
            super.setValue(ROLES, roles);
            return this;
        }



    }
}
