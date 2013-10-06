package com.sqrl;

import java.util.Arrays;

import com.sun.org.apache.xml.internal.security.utils.Base64;

public class SQRLAuthentication {
	
	/**
	 * Entire site URL that this authentication object was generated for.
	 * (E.g. "www.example.com/sqrl?KJA7nLFDQWWmvt10yVjNDoQ81uTvNorPrr53PPRJesz")
	 */
	private String siteURL;
	
	/**
	 * The crypto signature of the siteURL (512-bits)
	 */
	private byte[] identityAuthentication;
	
	/**
	 * The corresponding public key for the signature. This will allow the site to verify the
	 * identityAuthentication signature above.
	 */
	private byte[] identityPublicKey;

	public SQRLAuthentication(String siteURL, 
			                  byte[] identityAuthentication, byte[] identityPublicKey) {
		this.siteURL = siteURL;
		this.identityAuthentication = identityAuthentication;
		this.identityPublicKey = identityPublicKey;
	}

	public String getSiteURL() {
		return siteURL;
	}

	public byte[] getIdentityAuthentication() {
		return identityAuthentication;
	}

	public byte[] getIdentityPublicKey() {
		return identityPublicKey;
	}

	@Override
	public String toString() {
		return "SQRLAuthentication [siteURL=" + siteURL
				+ ", identityAuthentication=" + Base64.encode(identityAuthentication)
				+ ", identityPublicKey=" + Base64.encode(identityPublicKey)
				+ "]";
	}
}
