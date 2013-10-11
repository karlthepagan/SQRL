package com.sqrl.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMACSHA256 {
    public static byte[] mac(byte[] keyBytes, String message) {
        Mac mac;
        try {
            final SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "HmacSHA256");
            mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
            return mac.doFinal(message.getBytes());
        } catch (final NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (final InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }
}
