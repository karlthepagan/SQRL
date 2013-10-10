package com.sqrl.utils;

import static org.junit.Assert.*;

import org.junit.Test;

public class TestBase64Url {

    byte[] bytes = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a };
    String encoded = "AAECAwQFBgcICQo";

    @Test
    public void testEncode() {
        String testEncoded = Base64Url.encode(bytes);
        assertEquals(encoded, testEncoded);
    }

    @Test
    public void testDecode() {
        byte[] testDecoded = Base64Url.decode(encoded);
        assertArrayEquals(bytes, testDecoded);
    }

    byte[] masterIdentityKey = new byte[] { 0x57, 0x15, (byte) 0xc0, (byte) 0xd1, 0x57, 0x1c, (byte) 0xcd, 0x43, 0x7a,
            (byte) 0x9e, 0x3f, (byte) 0xfd, 0x6c, (byte) 0xc5, 0x65, 0x09, (byte) 0xe3, (byte) 0xfb, (byte) 0xa2, 0x0a,
            0x6a, (byte) 0x86, 0x62, (byte) 0xc2, 0x2b, (byte) 0x9e, 0x06, 0x20, 0x54, (byte) 0xd2, (byte) 0x97, 0x5b };
    String masterIdeneityKeyBase64 = "VxXA0VcczUN6nj_9bMVlCeP7ogpqhmLCK54GIFTSl1s";

    @Test
    public void testEncodeMasterIdentityKey() {
        String testEncoded = Base64Url.encode(masterIdentityKey);
        assertEquals(masterIdeneityKeyBase64, testEncoded);
    }
    
    @Test
    public void testDecodeMasterIdentityKey() {
        byte[] testDecoded = Base64Url.decode("VxXA0VcczUN6nj/9bMVlCeP7ogpqhmLCK54GIFTSl1s=");
        assertArrayEquals(masterIdentityKey, testDecoded);
    }
}
