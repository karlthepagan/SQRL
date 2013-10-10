package com.sqrl;

import com.sqrl.utils.Base64Url;

/**
 * Represents a SQRL identity.
 * 
 * This class is immutable, actions like password updates will cause the master
 * identity key and password salt to also change, so a new SQRL Idenity should
 * be created.
 */
public class SQRLIdentity {

    /** Optional identity name / identifier */
    private String identityName = "";

    /**
     * Private Master Identity Key (256-bits)
     * 
     * This key is XORed with the result of the password strengthening to create
     * the original master key
     */
    private byte[] masterIdentityKey;

    /**
     * Password Verify Value (128-bits)
     *
     * This is the first 128-bits of SHA256(scrypt_result) and is used to verify
     * the password was entered correctly.
     */
    private byte[] passwordVerify;

    /**
     * Encapsulates all of the password information
     */
    private SQRLPasswordParameters passwordParameters;

    public SQRLIdentity(String identityName, byte[] masterIdentityKey, byte[] passwordVerify, SQRLPasswordParameters passwordParameters) {
        this.identityName = identityName;
        this.masterIdentityKey = masterIdentityKey;
        this.passwordVerify = passwordVerify;
        this.passwordParameters = passwordParameters;
    }

    public String getIdentityName() {
        return identityName;
    }

    public byte[] getMasterIdentityKey() {
        return masterIdentityKey;
    }

    public byte[] getPasswordVerify() {
        return passwordVerify;
    }

    public SQRLPasswordParameters getPasswordParameters() {
        return passwordParameters;
    }

    @Override
    public String toString() {
        return "SQRLIdentity [identityName=" + identityName + ", masterIdentityKey="
                + Base64Url.encode(masterIdentityKey) + ", passwordVerify=" + Base64Url.encode(passwordVerify)
                + ", passwordParameters=" + passwordParameters + "]";
    }
}
