package jmdbtutorial.crypto.certificatetransparency;

import jmdbtutorial.crypto.Test_CryptoHashing;
import org.junit.Test;
import sun.security.x509.X500Name;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import static java.lang.System.out;

/**
 * https://embed.ct.digicert.com/
 * http://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art030
 * <p>
 * http://www.mkyong.com/java/java-https-client-httpsurlconnection-example/
 * <p>
 * https://tools.ietf.org/html/rfc6962#section-3.1
 */
public class Test_Obtain_SCT_embedded {

    @Test
    public void discover_cacerts_password() {
        out.println("cacert password: " + System.getProperty("encrypted_javatruststore_pwd"));
    }

    /**
     * https://tools.ietf.org/html/rfc6962#section-3.1 - OID for extension with SCT in it is: 1.3.6.1.4.1.11129.2.4.3
     * <p>
     * http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
     *
     * @throws Exception
     */
    @Test
    public void extract_embedded_sct() throws Exception {
        String https_url = "https://embed.ct.digicert.com/";
        URL url;

        url = new URL(https_url);
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();

       // con.setSSLSocketFactory();
        out.println(con.getResponseCode());

        printCertificateSummary(con);

        Certificate[] certificates = con.getServerCertificates();
        X509Certificate toVerify = (X509Certificate) certificates[0];
        List<X509Certificate> additionalCerts = new ArrayList<>();
        for (int i=1;i<certificates.length;i++) {
            additionalCerts.add((X509Certificate) certificates[i]);
        }

        Set<X509Certificate> trustedRootCerts = new HashSet<>(getTrustedRootCertificates());
        Set<X509Certificate> intermediateCerts = new HashSet<>();
        for (X509Certificate additionalCert : additionalCerts) {
            if (isSelfSigned(additionalCert)) {
                trustedRootCerts.add(additionalCert);
            } else {
                intermediateCerts.add(additionalCert);
            }
        }

        // Attempt to build the certification chain and verify it
        PKIXCertPathBuilderResult verifiedCertChain = verifyCertificate(toVerify, trustedRootCerts, intermediateCerts);

        //out.println("Verified chain: " + verifiedCertChain);

        out.println("Cert Path: " + verifiedCertChain.getCertPath().getType());
        out.println("Trust Anchor (Root Cert): " + verifiedCertChain.getTrustAnchor().getTrustedCert().getSubjectDN());


    }



    private static List<X509Certificate> getTrustedRootCertificates() throws Exception {
        String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
        FileInputStream is = new FileInputStream(filename);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        String password = "changeit";
        keystore.load(is, password.toCharArray());

        // This class retrieves the most-trusted CAs from the keystore
        PKIXParameters params = new PKIXParameters(keystore);

        List<X509Certificate> rootCerts = new ArrayList<>();
        // Get the set of trust anchors, which contain the most-trusted CA certificates
        Iterator it = params.getTrustAnchors().iterator();
        while( it.hasNext() ) {
            TrustAnchor ta = (TrustAnchor)it.next();
            // Get certificate
            X509Certificate cert = ta.getTrustedCert();
            rootCerts.add(cert);
        }
        return rootCerts;
    }
    private static PKIXCertPathBuilderResult verifyCertificate(
            X509Certificate cert, Set<X509Certificate> trustedRootCerts,
            Set<X509Certificate> intermediateCerts) throws GeneralSecurityException {

        // Create the selector that specifies the starting certificate
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(cert);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
        for (X509Certificate trustedRootCert : trustedRootCerts) {
            trustAnchors.add(new TrustAnchor(trustedRootCert, null));
        }

        // Configure the PKIX certificate builder algorithm parameters
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(
                trustAnchors, selector);

        // Disable CRL checks (this is done manually as additional step)
        pkixParams.setRevocationEnabled(false);

        // Specify a list of intermediate certificates
        CertStore intermediateCertStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(intermediateCerts));
        pkixParams.addCertStore(intermediateCertStore);

        // Build and verify the certification chain
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder
                .build(pkixParams);
        return result;
    }

    public static boolean isSelfSigned(X509Certificate cert) throws CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException {
        try {
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (SignatureException sigEx) {
            return false;
        } catch (InvalidKeyException keyEx) {
            return false;
        }
    }

    private void printCertificateSummary(HttpsURLConnection con) throws Exception {

        for (Certificate certificate : con.getServerCertificates()) {
            if (!(X509Certificate.class.isAssignableFrom(certificate.getClass()))) {
                throw new RuntimeException("Certificate is not an X509 cert!: " + certificate);
            }
            X509Certificate x509Certificate = (X509Certificate) certificate;

            X500Name name = (X500Name) x509Certificate.getSubjectDN();
            out.println("Certificate Subject: " + name.getCommonName());

            out.println("Certificate issuer: " + x509Certificate.getIssuerDN());


        }

    }

    private static void print_https_cert(HttpsURLConnection con) throws Exception {

        if (con != null) {


            out.println("Response Code : " + con.getResponseCode());
            out.println("Cipher Suite : " + con.getCipherSuite());
            out.println("\n");

            Certificate[] certs = con.getServerCertificates();
            for (Certificate cert : certs) {
                X509Certificate x509 = (X509Certificate) cert;
                out.println("X509 constraints: " + x509.getBasicConstraints());
                out.println("X509 non critical extensions: " + x509.getNonCriticalExtensionOIDs());
                out.println("X509 critical extensions: " + x509.getCriticalExtensionOIDs());
                out.println("X509: " + x509);
                out.println("Cert Type : " + cert.getType());
                out.println("Cert Encoded : " + Test_CryptoHashing.printHexBytes(cert.getEncoded(), 0));
                out.println("Cert Public Key Algorithm : " + cert.getPublicKey().getAlgorithm());
                out.println("Cert Public Key Format : " + cert.getPublicKey().getFormat());
                out.println("\n");
            }


        }

    }

    private static void print_content(HttpsURLConnection con) throws Exception {
        if (con != null) {


            out.println("****** Content of the URL ********");
            BufferedReader br =
                    new BufferedReader(
                            new InputStreamReader(con.getInputStream()));

            String input;

            while ((input = br.readLine()) != null) {
                out.println(input);
            }
            br.close();


        }

    }


}
