package jmdbtutorial.crypto;


import org.junit.Test;

import static java.lang.Byte.toUnsignedInt;
import static java.lang.System.out;
import static jmdbtutorial.crypto.Test_CryptoHashing.prinBytesBinary;
import static jmdbtutorial.crypto.Test_CryptoHashing.printHexBytes;

public class Test_Binary_Hex {

    @Test
    public void binary_versions() {

        byte[] bytes = new byte[] {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

        out.println(printHexBytes(bytes));
        out.println(prinBytesBinary(bytes));

    }

    @Test
    public void binary_table() {
        byte[] index = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

        out.println("         " + printHexBytes(index));

        for (byte b : index) {

            byte[] row = bitshiftandAdd(index, b);
            out.println(printHexBytes(new byte[] {b}) + prinBytesBinary(row));

        }
    }

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

}
