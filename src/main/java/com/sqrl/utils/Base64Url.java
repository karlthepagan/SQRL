package com.sqrl.utils;

import org.apache.commons.codec.binary.Base64;

public class Base64Url {
    private static Base64 base64 = new Base64(256, null, true);
    public static String encode(byte[] bytes) {
        return new String(base64.encode(bytes));
    }
    
    public static byte[] decode(String base64UrlStr) {
        return base64.decode(base64UrlStr);
    }
}
