package com.sqrl.client;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.lambdaworks.crypto.SCrypt;
import com.sqrl.SQRLAuthentication;
import com.sqrl.SQRLIdentity;
import com.sqrl.crypto.Curve25519;
import com.sqrl.exception.PasswordVerifyException;
import com.sqrl.exception.SQRLException;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

public class Client {

    public static void main(String[] args) throws Base64DecodingException, GeneralSecurityException,
            PasswordVerifyException {
        // stored user profile information, This should be loaded off disk for
        // an existing
        // sqrl identity OR generated fresh for a new sqrl identity
        // 256-bit private master identity key
        // 64-bit password salt
        // 128-bit password verify value
        byte[] privateMasterIdentityKey = Base64.decode("VxXA0VcczUN6nj/9bMVlCeP7ogpqhmLCK54GIFTSl1s=");
        byte[] passwordSalt = Base64.decode("Ze6tha++1E0=");
        byte[] passwordVerify = Base64.decode("TlA6rTzAcCYWm8o/UF6sk3i8mU2JR/db34/6nE3HKDg=");

        SQRLIdentity exampleIdentity = new SQRLIdentity("example identity", privateMasterIdentityKey, passwordVerify,
                passwordSalt);
        /**
         * LOGIN - Example
         */

        // This is the web-site URL the user is going to login to using SQRL.
        // This URL will be decoded from the QR-code displayed on the site
        String siteURL = "www.example.com/sqrl?KJA7nLFDQWWmvt10yVjNDoQ81uTvNorPrr53PPRJesz";
        try {
            SQRLAuthentication authentication = createAuthentication(siteURL, exampleIdentity);
            System.out.println("AUTHENTICATION RESULT: ");
            System.out.println(authentication);
            System.out.println();
        } catch (SQRLException e) {
            System.out.println("Error creating authentication for " + getTLD(siteURL) + ":" + e.getMessage());
            e.printStackTrace();
        }

        /**
         * CHANGE PASSWORD - Example
         */
        // TODO

        /**
         * EXPORT MASTER KEY - Example
         */
        // TODO

    }

    public static SQRLAuthentication createAuthentication(String siteURL, SQRLIdentity identity) throws SQRLException {
        // STEP 0: Have the user enter the password for the identity.
        // example user-entered password
        String password = "password";

        // STEP 1: Scrypt the password + passwordSalt
        // This is the expensive operation and its parameters should be tuned so
        // that this
        // operation takes between 1-2 seconds to perform.
        byte[] scryptResult = scrypt(password, identity);
        System.out.println("STEP 1: ");
        System.out.println("Scrypt of password + salt: " + Base64.encode(scryptResult));
        System.out.println();

        // STEP 2: Check the sha256 hash of the result from STEP 1 verse the
        // stored passwordVerify
        // value.
        byte[] passwordCheck = sha256(scryptResult);
        System.out.println("STEP 2: ");
        System.out.println("Password Verify: " + Base64.encode(identity.getPasswordVerify()));
        System.out.println("Password Check : " + Base64.encode(passwordCheck));
        boolean passwordCheckSuccess = arrayEqual(passwordCheck, identity.getPasswordVerify());
        System.out.println("Password Check Result: " + (passwordCheckSuccess ? "PASS" : "FAIL"));
        if (!passwordCheckSuccess) {
            System.out.println("Password Check Failed!");
            System.out.println();
            throw new PasswordVerifyException();
        }
        System.out.println();

        // STEP 3: XOR the master identity key from the SQRLIdentity with the
        // result from STEP 1
        // to create the original master key
        byte[] originalMasterKey = xor(identity.getMasterIdentityKey(), scryptResult);
        System.out.println("STEP 3: ");
        System.out.println("Original Master Key: " + Base64.encode(originalMasterKey));
        System.out.println();

        // STEP 4: HMACSHA-256 the master key result from STEP 3: with the site
        // TLD
        byte[] privateKey = hmacSHA256(originalMasterKey, getTLD(siteURL));
        System.out.println("STEP 4: ");
        System.out.println("Private Key Length: " + privateKey.length * 8 + " bits");
        System.out.println("Private Key: " + Base64.encode(privateKey));
        System.out.println();

        // STEP 5: Synthesize a public key by using the result from STEP 4
        byte[] publicKey = Curve25519.publickey(privateKey);
        System.out.println("STEP 5: ");
        System.out.println("Public Key Length: " + publicKey.length * 8 + " bits");
        System.out.println("Public Key: " + Base64.encode(publicKey));
        System.out.println();

        // STEP 6: Sign the entire site URL with the private key from STEP 4.
        byte[] signature = Curve25519.signature(siteURL.getBytes(Charset.forName("UTF-8")), privateKey, publicKey);
        System.out.println("STEP 6: ");
        System.out.println("Signature for " + siteURL);
        System.out.println("Signature Length: " + signature.length * 8);
        System.out.println("Signature: " + Base64.encode(signature));
        System.out.println();

        // Return authentication object containing all the
        // outputs which are to be sent to the server.
        return new SQRLAuthentication(siteURL, signature, publicKey);
    }

    // //////////// HELPER FUNCTIONS //////////////////

    private static String getTLD(String siteURL) {
        return siteURL.split("/sqrl")[0];
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] output = new byte[a.length];
        for (int i = output.length - 1; i >= 0; --i) {
            output[i] = (byte) (a[i] ^ b[i]);
        }
        return output;
    }

    private static boolean arrayEqual(byte[] a, byte[] b) {
        if (a.length != b.length)
            return false;

        for (int i = a.length - 1; i >= 0; --i) {
            if (a[i] != b[i])
                return false;
        }
        return true;
    }

    private static byte[] hmacSHA256(byte[] keyBytes, String message) {
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

    private static byte[] sha256(byte[] bytes) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] scrypt(String password, SQRLIdentity sqrlIdentity) {
        // CPU Cost - This should be tuned so that this takes between 1 and 2
        // seconds to calculate
        int N = (int) Math.pow(2, 14);
        // Memory Cost
        int r = 8;
        // Parallelization
        int p = 1;
        // output length : 256-bits
        int dkLen = 32;

        System.out.println("N: " + N);
        try {
            return SCrypt.scrypt(password.getBytes(), sqrlIdentity.getPasswordSalt(), N, r, p, dkLen);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }

}
