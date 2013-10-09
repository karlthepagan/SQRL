package com.sqrl.client;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.lambdaworks.crypto.SCrypt;
import com.sqrl.SQRLAuthentication;
import com.sqrl.SQRLIdentity;
import com.sqrl.SQRLPasswordParameters;
import com.sqrl.crypto.Curve25519;
import com.sqrl.exception.PasswordVerifyException;
import com.sqrl.exception.SQRLException;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

public class Client {
    private static final DecimalFormat df = new DecimalFormat("#.##");
    
    public static void main(String[] args) throws Base64DecodingException, GeneralSecurityException,
            SQRLException {
        
        String warning = "WARNING: THIS CODE IS REALLY REALLY REALLY EXPIREMENTAL, DO NOT USE FOR ANYTHING "
                       + "EXCEPT LEARNING HOW SOME OF THE CRYPTO BEHIND SQRL CAN BE IMPLEMENTED.";
        System.err.println(warning);
        
        // Because this code is so experimental, if its not being maintained anymore, then don't let it even run
        //  if the current date is great than January 1, 2014
        if ( new Date().getTime() >  1388556000L * 1000L ) {
            System.err.println();
            System.err.println("ERROR: THIS CODE IS TOO OLD!, if it had been maintained, "
                             + "this time check would have been removed");
            System.exit(-1);
        }
        
        // stored user profile information, This should be loaded off disk for an existing sqrl identity OR 
        // generated fresh for a new sqrl identity
        //    256-bit private master identity key
        //    64-bit password salt
        //    128-bit password verify value
        byte[] privateMasterIdentityKey = Base64.decode("VxXA0VcczUN6nj/9bMVlCeP7ogpqhmLCK54GIFTSl1s=");
        byte[] passwordSalt = Base64.decode("Ze6tha++1E0=");
        byte[] passwordVerify = Base64.decode("wMS9dlme6gyPDkT9obtWiQyLYiLLC9nv+QJICM3xgXI=");

        SQRLPasswordParameters examplePasswordParameters = new SQRLPasswordParameters(passwordSalt, 16,8,12);
        SQRLIdentity exampleIdentity = new SQRLIdentity("example identity", privateMasterIdentityKey, 
                                                        passwordVerify, examplePasswordParameters);
        
        /**
         * LOGIN - Example
         */
        {
            System.out.println("~~~Begin LOGIN example~~~");
            // STEP 0: Have the user enter the password for the identity.
            // example user-entered password
            String password = "password";
            
            // This is the web-site URL the user is going to login to using SQRL.
            // This URL will be decoded from the QR-code displayed on the site
			String siteURL = "www.example.com/~bob/sqrl.php?d=5&ip=192.168.1.1&"
					+ "webnonce=KJA7nLFDQWWmvt10yVjNDoQ81uTvNorPrr53PPRJesz";
            try {
                SQRLAuthentication authentication = createAuthentication(exampleIdentity, password, siteURL);
                System.out.println("LOGIN example result: ");
                System.out.println(authentication);
                System.out.println();
            } catch (SQRLException e) {
                System.out.println("Error creating authentication for " + getTLD(siteURL) + ":" + e.getMessage());
                e.printStackTrace();
            }
        }
        
        /**
         * CHANGE PASSWORD - Example
         */
        {
            System.out.println("~~~Begin CHANGE PASSWORD example~~~");
            // STEP 0: Have the user enter the current password for the identity.
            // example user-entered password
            String currentPassword = "password";
            
            // STEP 1: Get the new password from the user
            // User entered password, should probably have them enter twice because there is no returning from the change
            // once its persisted on disk
            String newPassword = "newpassword";
            SQRLIdentity changedPasswordIdentity = changePassword(exampleIdentity, currentPassword, newPassword);
            System.out.println("CHANGE PASSWORD RESULT: ");
            System.out.println(changedPasswordIdentity);
            System.out.println();
        }
        
        /**
         * EXPORT MASTER KEY - Example
         */
        {
            System.out.println("~~~Begin EXPORT MASTER IDENTITY example~~~");
            // STEP 0: Have the user enter the current password for the identity.
            // example user-entered password
            String currentPassword = "password";
        
            SQRLIdentity exportedIdentity = exportMasterKey(exampleIdentity, currentPassword);
            
            System.out.println("EXPORT MASTER KEY RESULT: ");
            System.out.println(exportedIdentity);
            System.out.println();

            // TODO pack the exported identity into the agreed upon export format, the current proposal is:
            //        8-bit signature algorithm version
            //        256-bit encrypted master key
            //          8-bit password algorithm version
            //         64-bit per-password nonce
            //         64-bit per-password verifier
            //         16-bit computation burden spec (10 bit mantissa + 6 bit exp)
        }
    }

    public static SQRLIdentity exportMasterKey(SQRLIdentity identity, String password) throws SQRLException {
        // STEP 1: Scrypt the current password + passwordSalt
        // This is the expensive operation and its parameters should be tuned so
        // that this operation takes between 1-2 seconds to perform.
        byte[] scryptResult = scrypt(password, identity.getPasswordParameters());
        System.out.println("STEP 1: ");
        System.out.println("Scrypt of password + salt: " + Base64.encode(scryptResult));
        System.out.println();
        
        // STEP 2: Check the sha256 hash of the result from STEP 1 verse the
        // current stored passwordVerify value.
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
        // result from STEP 1 to create the original master key
        byte[] originalMasterKey = xor(identity.getMasterIdentityKey(), scryptResult);
        System.out.println("STEP 3: ");
        System.out.println("Original Master Key: " + Base64.encode(originalMasterKey));
        System.out.println();
        
        // STEP 4: Create a new password salt
        byte[] newPasswordSalt = secureRandom(8); // 64-bit salt
        System.out.println("STEP 4: ");
        System.out.println("New Password Salt: " + Base64.encode(newPasswordSalt));
        System.out.println();
        
        // STEP 5: SCrypt the current password and newPasswordSalt with WAY more difficult SCryptParameters
        SQRLPasswordParameters newPasswordParameters = new SQRLPasswordParameters(newPasswordSalt, 18, 8, 90);
        byte[] newScryptResult = scrypt(password, newPasswordParameters);
        System.out.println("STEP 5: ");
        System.out.println("SCrypt of New Password + Salt: " + Base64.encode(newScryptResult));
        System.out.println();
        
        // STEP 6: SHA256 the SCrypt result from STEP 5 to create the new password verifier
        byte[] newPasswordVerify = sha256(newScryptResult);
        System.out.println("STEP 6: ");
        System.out.println("New Password Verify: " + Base64.encode(newPasswordVerify));
        System.out.println();
        
        // STEP 7: XOR the original master key with the SCrypt result from STEP 5 to create the new master identity key
        byte[] newMasterIdentityKey = xor(originalMasterKey, newScryptResult);
        System.out.println("STEP 7: ");
        System.out.println("New Master Identity Key: " + Base64.encode(newMasterIdentityKey));
        System.out.println();
        
        // Return a new SQRLIdentity with the new password salt, password verify, password parameters 
        //  and master identity key
        return new SQRLIdentity(identity.getIdentityName(), newMasterIdentityKey, newPasswordVerify, newPasswordParameters);
    }
    
    public static SQRLIdentity changePassword(SQRLIdentity identity, String currentPassword, String newPassword) throws SQRLException {
        // STEP 1: Scrypt the current password + passwordSalt
        // This is the expensive operation and its parameters should be tuned so
        // that this operation takes between 1-2 seconds to perform.
        byte[] scryptResult = scrypt(currentPassword, identity.getPasswordParameters());
        System.out.println("STEP 1: ");
        System.out.println("Scrypt of password + salt: " + Base64.encode(scryptResult));
        System.out.println();

        // STEP 2: Check the sha256 hash of the result from STEP 1 verse the
        // current stored passwordVerify value.
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
        // result from STEP 1 to create the original master key
        byte[] originalMasterKey = xor(identity.getMasterIdentityKey(), scryptResult);
        System.out.println("STEP 3: ");
        System.out.println("Original Master Key: " + Base64.encode(originalMasterKey));
        System.out.println();
        
        // STEP 4: Create a new password salt
        byte[] newPasswordSalt = secureRandom(8); // 64-bit salt
        System.out.println("STEP 4: ");
        System.out.println("New Password Salt: " + Base64.encode(newPasswordSalt));
        System.out.println();

        // STEP 5: SCrypt the newPassword and newPasswordSalt
        SQRLPasswordParameters newPasswordParameters = new SQRLPasswordParameters(newPasswordSalt, 16, 8, 12);
        byte[] newScryptResult = scrypt(newPassword, newPasswordParameters);
        System.out.println("STEP 5: ");
        System.out.println("SCrypt of New Password + Salt: " + Base64.encode(newScryptResult));
        System.out.println();
        
        // STEP 6: SHA256 the SCrypt result from STEP 5 to create the new password verifier
        byte[] newPasswordVerify = sha256(newScryptResult);
        System.out.println("STEP 6: ");
        System.out.println("New Password Verify: " + Base64.encode(newPasswordVerify));
        System.out.println();

        // STEP 7: XOR the original master key with the SCrypt result from STEP 5 to create the new master identity key
        byte[] newMasterIdentityKey = xor(originalMasterKey, newScryptResult);
        System.out.println("STEP 7: ");
        System.out.println("New Master Identity Key: " + Base64.encode(newMasterIdentityKey));
        System.out.println();
        
        // Return a new SQRLIdentity with the new password salt, password verify, and master identity key
        // Note: the password is not permanently changed until this new identity object is written over the
        //       old identity on disk.
        return new SQRLIdentity(identity.getIdentityName(), newMasterIdentityKey, newPasswordVerify, newPasswordParameters);
    }

    public static SQRLAuthentication createAuthentication(SQRLIdentity identity, String password, String siteURL) throws SQRLException {
        // STEP 1: Scrypt the password + passwordSalt
        // This is the expensive operation and its parameters should be tuned so
        // that this operation takes between 1-2 seconds to perform.
        byte[] scryptResult = scrypt(password, identity.getPasswordParameters());
        System.out.println("STEP 1: ");
        System.out.println("Scrypt of password + salt: " + Base64.encode(scryptResult));
        System.out.println();

        // STEP 2: Check the sha256 hash of the result from STEP 1 verse the
        // stored passwordVerify value.
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
        // result from STEP 1 to create the original master key
        byte[] originalMasterKey = xor(identity.getMasterIdentityKey(), scryptResult);
        System.out.println("STEP 3: ");
        System.out.println("Original Master Key: " + Base64.encode(originalMasterKey));
        System.out.println();

        // STEP 4: HMACSHA-256 the master key result from STEP 3: with the site TLD
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

	/**
	 * Extract the TLD from the supplied site URL
	 * 
	 * @param siteURL
	 *            The site's complete URL to be disassembled.
	 * @return The TLD for the give site URL
	 */
    private static String getTLD(String siteURL) {
		// TODO
		String tld = new String();
		int d = 0;

		tld = siteURL.split( "\\?" )[0];
		String params[] = siteURL.split( "\\?" )[1].split( "&" );

		for ( String param : params )
		{
			if ( param.startsWith( "d=" ) )
			{
				try {
					d = Integer.parseInt( param.split( "=" )[1] );
				}
				catch (NumberFormatException e){
					d = 0;
				}
			}
		}

		// Find the first / to find the end of the normal TLD
		int endOfTld = tld.indexOf( "/" );
		// Add the value of d, to get the SQRL TLD
		endOfTld += d;

		tld = tld.substring( 0, endOfTld );
		System.out.println( "TLD + " + tld + "\n");
		return tld;
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

    private static byte[] scrypt(String password, SQRLPasswordParameters sqrlPassword) {
        System.out.println("N: " + (1 << sqrlPassword.getHashN()));
        try {
            long startTime = System.currentTimeMillis();
            byte[] scryptResult = SCrypt.scrypt(password.getBytes(), sqrlPassword.getPasswordSalt(), 
                                                1 << sqrlPassword.getHashN(), sqrlPassword.getHashR(), 
                                                sqrlPassword.getHashP(), sqrlPassword.getHashLength());
            long elapsedTime = System.currentTimeMillis() - startTime;
            System.out.println("SCrypt (N = " + sqrlPassword.getHashN() + ") took " + 
                               df.format(elapsedTime/1000.0) + " seconds.");
            return scryptResult;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static SecureRandom rand = new SecureRandom();
    private static byte[] secureRandom(int numBytes) {
        byte[] randBytes = new byte[numBytes];
        rand.nextBytes(randBytes);
        return randBytes;
    }
}
