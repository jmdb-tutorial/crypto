package jmdbtutorial.crypto;


import org.junit.Test;

import static java.lang.System.out;
import static jmdbtutorial.crypto.Test_CryptoHashing.printBytesBinary;
import static jmdbtutorial.crypto.Test_CryptoHashing.printHexBytes;

public class Test_Binary_Hex {

    @Test
    public void binary_versions() {

        byte[] bytes = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

        out.println(printHexBytes(bytes));
        out.println(printBytesBinary(bytes));

    }

    @Test
    public void hexes() {
        out.println("0xF  - " + printBytesBinary(new byte[] {0xF}));
        out.println("0x0F - " + printBytesBinary(new byte[] {0x0F}));
    }

    @Test
    public void binary_table() {
        byte[] index = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

        out.println("         " + printHexBytes(index));

        for (byte b : index) {

            byte[] row = bitshiftandAdd(index, b);
            out.println(printHexBytes(new byte[] {b}) + printBytesBinary(row));

        }
    }

    /**
     * Because a byte in java is a signed int we cant set 11111111 by specifying 0xFF because it
     * is too big. 11111111 is infact -1 (see bytes_and_bits test and print_signed_bytes_as_binary)
     * So in order to add the two hex numbers together, which are going to be like:
     *
     * in       toAdd
     * 00001111 00001111
     *
     * We first bitshift the one on the right so it looks like:
     *
     * 00001111 11110000
     *
     * and then OR them together to get:
     *
     * 11111111
     *
     */
    public static byte[] bitshiftandAdd(byte[] bytes, byte toAdd) {
        byte[] results = new byte[bytes.length];
        for (int i=0; i<bytes.length; ++i) {
            byte in = bytes[i];
            byte result = (byte)(toAdd << 4);
            results[i] = (byte)(in ^ result);
        }
        return results;
    }

    @Test
    public void add_hex() {
        byte hex = 0x1;
        byte add = 0x1 << 4;

        byte result = (byte)(hex ^ add);


        out.println(printHexBytes(new byte[] {result}));
    }

    @Test
    public void hex_format() {
        out.println("0x01 = " + printBytesBinary(new byte[] {0x01}));
        out.println("0x11 = " + printBytesBinary(new byte[] {0x11}));

        out.println("0x" + printHexBytes(new byte[] {0x4f}, 0) + " = " + printBytesBinary(new byte[] {0x4f}));
    }

}
