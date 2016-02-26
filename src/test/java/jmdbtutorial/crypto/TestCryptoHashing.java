package jmdbtutorial.crypto;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.Base64;

import static java.lang.String.format;
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


        out.println("Input            : " + input);
        out.println("Digest Length    : " + messageDigest.getDigestLength());
        out.println("Algorithm        : " + messageDigest.getAlgorithm());


        String base64Hash = new String(Base64.getEncoder().encode(raw));

        out.println("\nbase64           : " + base64Hash);
        out.println("hex              : " + printHexBytes(raw, 1).trim() + "\n");

        printByteArray(raw);

    }



    @Test
    public void byte_buffers() throws Exception {
        byte[] arr = {0x00, 0xF};
        ByteBuffer wrapped = ByteBuffer.wrap(arr).order(ByteOrder.BIG_ENDIAN);

        short num = wrapped.getShort(); // 1
        out.println("num= " + num);


        ByteBuffer dbuf = ByteBuffer.allocate(2);
        dbuf.putShort(num);
        byte[] bytes = dbuf.array(); // { 0, 1 }
        out.println(printRawBytes(bytes));
    }

    private static final char[] hexCode = "0123456789abcdef".toCharArray();




    public static String printHexBytes(byte[] data) {
        return printHexBytes(data, 9);
    }

    /**
     * http://www.javamex.com/tutorials/conversion/decimal_hexadecimal.shtml
     * Also by looking in DataTypeconverter
     */
    public static String printHexBytes(byte[] data, int padding) {

        StringBuilder r = new StringBuilder(data.length * 2);
        for (byte b : data) {
            r.append(padString("", ' ', padding));
            r.append(hexCode[(b >> 4) & 0xF]);
            r.append(hexCode[(b & 0xF)]);
        }
        return r.toString();

    }




    @Test
    public void bytes_and_bits() {
        byte[] bytes = new byte[] {0, 1, -1};
        printByteArray(bytes);


    }

    @Test
    public void printOutAString() throws UnsupportedEncodingException {
        String input = "ABC€$&\u00E8";

        out.println("String   : " + input);
        out.println("\nUTF-8");
        out.println("-----");

        StringBuilder sb = new StringBuilder();
        for (Character c :  input.toCharArray()) {
            String s = c.toString();
            sb.append(padString(c.toString(), ' ', 9 * s.getBytes("UTF-8").length));

        }
        out.println("Input            : " + sb.toString());
        printByteArray(input.getBytes("UTF-8"));
    }

    private static void printByteArray(byte[] bytes) {
        int[] unsignedBytes = unsignedBytes(bytes);

        out.println(format("bytes.length     : %9d", bytes.length));
        out.println("bytes (unsigned) : " + printRawBytes(bytes));
        out.println("bytes (signed)   : " + printIntBytes(unsignedBytes));
        out.println("bytes (hex)      : " + printHexBytes(bytes));
        out.println("bytes (binary)   : " + printIntBytesBinary(unsignedBytes));
    }


    private static String printIntBytesBinary(int[] unsignedBytes) {
        StringBuilder sb = new StringBuilder();
        for (int b : unsignedBytes) {
            sb.append(" ").append(padString(formatBinaryString(Integer.toBinaryString(b)), '0', 8));
        }
        return sb.toString();
    }

    private static String padString(String input, char padding, int width) {
        if (input.length() >= width) {
            return input;
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < (width - input.length()); ++i) {
            sb.append(padding);
        }
        sb.append(input);
        return sb.toString();
    }

    private static int[] unsignedBytes(byte[] bytes) {
        int[] result = new int[bytes.length];

        for (int i = 0; i < bytes.length; ++i) {
            result[i] = bytes[i] & 0xFF;
        }
        return result;
    }

    public static String formatBinaryString(String binaryString) {
        return formatBinaryString(binaryString, 8);
    }

    public static String formatBinaryString(String binaryString, int blockSize) {
        StringBuilder sb = new StringBuilder();


        for (int i = 0; i < binaryString.length(); ++i) {
            sb.append(binaryString.charAt(i));
            if ((i + 1) % blockSize == 0) {
                sb.append(" ");
            }
        }
        return sb.toString().trim();
    }

    @Test
    public void bigend_littlend() throws Exception {
        String bigendian = "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d";
        String littlendian = reverseHex(bigendian);

        out.println(littlendian);
    }

    public static String printRawBytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < bytes.length; ++i) {
            Byte B = bytes[i];
            sb.append(format("%9d", B.intValue()));
        }
        return sb.toString();
    }

    public static String printIntBytes(int[] bytes) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < bytes.length; ++i) {
            int l = bytes[i];
            sb.append(format("%9d", l));
        }
        return sb.toString();
    }

    public static String printUnsignedBytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < bytes.length; ++i) {
            Byte B = bytes[i];
            sb.append(format("%9d", B.intValue() & 0xFF));
        }
        return sb.toString();
    }

    public static String reverseHex(String originalHex) {
        int lengthInBytes = originalHex.length() / 2;
        char[] chars = new char[lengthInBytes * 2];
        for (int index = 0; index < lengthInBytes; index++) {
            int reversedIndex = lengthInBytes - 1 - index;
            chars[reversedIndex * 2] = originalHex.charAt(index * 2);
            chars[reversedIndex * 2 + 1] = originalHex.charAt(index * 2 + 1);
        }
        return new String(chars);
    }
}
