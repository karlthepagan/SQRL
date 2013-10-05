package com.sqrl.client;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.util.Arrays;

import com.sqrl.crypto.Curve25519;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

public class Client {

	public static void main(String[] args) throws Base64DecodingException {
		// init bouncy castle
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		// stored user profile information
		//   512-bit private master identity key (this should be encrypted with hmacKey)
		//    64-bit password salt
		//   128-bit password verify value
		
		byte[] privateMasterIdentityKey = Base64.decode("/ahkohTR4emXC4fcTCHzqtA86MvcUTWd9fudoJ6RHVJR"
													  + "qui7R7L6sRntcybwSzQQiNATaXjCthHPjG0+0ixC8w==");
		byte[] passwordSalt = Base64.decode("Ze6tha++1E0=");
		byte[] passwordVerify = Base64.decode("6Q0nbTTXUIFl3ykqxsPYHA==");
		
		System.out.println("Private Master Key Length: " + privateMasterIdentityKey.length * 8 + " bits");
		System.out.println("Private Master Key: " + Base64.encode(privateMasterIdentityKey));

		System.out.println("Password salt: " + Base64.encode(passwordSalt));
		// User password
		String password = "password";
		// CPU Cost
		int N = (int)Math.pow(2, 14);
		// Memory Cost
		int r = 8;
		// Parallelization
		int p = 1;
		// output length : 512-bits
		int dkLen = 64;
		
		byte[] scryptResult = SCrypt.generate(password.getBytes(), passwordSalt, N, r, p, dkLen);
		System.out.println("Scrypt of password + salt: " + Base64.encode(scryptResult));

		byte[] passwordCheck = Arrays.copyOfRange(SCrypt.generate(password.getBytes(), passwordSalt, N + 1, r, p, dkLen), 0, 16);
		System.out.println("Password Verify: " + Base64.encode(passwordVerify));
		System.out.println("Password Check : " + Base64.encode(passwordCheck));
		boolean passwordCheckSuccess = Arrays.areEqual(passwordCheck, passwordVerify);
		System.out.println("Password Check Result: " + (passwordCheckSuccess ? "PASS" : "FAIL"));
		if ( !passwordCheckSuccess ) {
			System.out.println("Password Check Failed!");
			System.exit(-1);
		}
		
		byte[] hmacKey = xor(privateMasterIdentityKey, scryptResult);
		
		System.out.println("HMac Key: " + Base64.encode(hmacKey));
		
		String siteURL = "www.example.com";
		
		byte[] privateKey = hmacSHA512(hmacKey, siteURL);
		System.out.println("Private Key Length: " + privateKey.length * 8);
		System.out.println("Private Key: " + Base64.encode(privateKey));
		
		byte[] publicKey = Curve25519.publickeyFrom512(privateKey);
		System.out.println("Public Key Length: " + publicKey.length * 8);
		System.out.println("Public Key: " + Base64.encode(publicKey));
		
		String message = "www.example.com/sqrl?KJA7nLFDQWWmvt10yVjNDoQ81uTvNorPrr53PPRJesz";
		byte[] signature = Curve25519.signatureFrom512(message.getBytes(Charset.forName("UTF-8")), privateKey, publicKey);
		System.out.println("Signature for " + message);
		System.out.println("Signature Length: " + signature.length * 8);
		System.out.println("Signature: " + Base64.encode(signature));
		
		
		try {
			boolean valid = Curve25519.checkvalid(signature, message.getBytes(Charset.forName("UTF-8")), publicKey);
			System.out.println("Signature is " + (valid ? "VALID" : "INVALID"));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private static byte[] xor(byte[] a, byte[] b) {
		byte[] output = new byte[a.length];
		for (int i = output.length - 1; i >= 0; --i) {
			output[i] = (byte) (a[i] ^ b[i]);
		}
		return output;
	}
	
	private static byte[] hmacSHA512(byte[] keyBytes, String message) {
		SecretKey           key = new SecretKeySpec(keyBytes, "HMac-SHA512");
		Mac                 mac;

		try {
			mac = Mac.getInstance("HMac-SHA512", "BC");
			mac.init(key);
			mac.reset();
			mac.update(message.getBytes(), 0, message.getBytes().length);
			
			return mac.doFinal();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}
