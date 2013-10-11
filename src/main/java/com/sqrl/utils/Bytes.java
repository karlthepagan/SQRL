package com.sqrl.utils;

public class Bytes {
    public static byte[] xor(byte[] a, byte[] b) {
        byte[] output = new byte[a.length];
        for (int i = output.length - 1; i >= 0; --i) {
            output[i] = (byte) (a[i] ^ b[i]);
        }
        return output;
    }

    public static boolean arrayEqual(byte[] a, byte[] b) {
        if (a.length != b.length)
            return false;

        for (int i = a.length - 1; i >= 0; --i) {
            if (a[i] != b[i])
                return false;
        }
        return true;
    }
}
