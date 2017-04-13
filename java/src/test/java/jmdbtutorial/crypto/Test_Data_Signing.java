package jmdbtutorial.crypto;

import org.junit.Test;

import java.net.URL;
import java.security.KeyPair;

import static jmdbtutorial.crypto.DataSigning.*;
import static jmdbtutorial.platform.ClassPathResources.getResourceRelativeTo;
import static jmdbtutorial.platform.Console.printlnf;

/**
 * https://docs.oracle.com/javase/tutorial/security/apisign/step2.html
 * Must add .txt files to you compiler patterns in intellij
 */
public class Test_Data_Signing {

    private KeyPair keyPair;
    private String signatureBase64;
    private String publicKeyBase64;

    @Test
    public void sign_some_data() throws Exception {

        URL dataUrl = getResourceRelativeTo(this, "testData.txt");

        keyPair = generateKeyPair();

        signatureBase64 = signData(dataUrl, keyPair.getPrivate());

        publicKeyBase64 = encodeAsBase64(keyPair.getPublic());

        boolean result = verifyData(publicKeyBase64, signatureBase64, dataUrl);

        printlnf("Signature (base64)     : [%s]", signatureBase64);
        printlnf("Public Key (base64)    : [%s]", publicKeyBase64);
        printlnf("Result of verification : [%s]", result);

    }


}
