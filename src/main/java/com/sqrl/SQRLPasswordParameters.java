package com.sqrl;

import com.sun.org.apache.xml.internal.security.utils.Base64;

/**
 * Encapsulates all of the password encryption parameters.
 */
public class SQRLPasswordParameters {
    /**
     * Password Salt (64-bits)
     *
     * This is a randomly generated salt value generated when the password is
     * first set. Whenever the password changes, this also should change.
     */
    private byte[] passwordSalt;

    /**
     * SCrypt number of rounds
     */
    private int N;

    /**
     * SCrypt memory factor
     */
    private int r;

    /**
     * SCrypt parallelization factor
     */
    private int p;

    /**
     * SCrypt hash output length
     */
    private int dkLen;

    public SQRLPasswordParameters(byte[] passwordSalt, int N, int r, int p) {
        this.passwordSalt = passwordSalt;
        this.N = N;
        this.r = r;
        this.p = p;
        this.dkLen = 32;
    }

    public byte[] getPasswordSalt() {
        return passwordSalt;
    }

    public int getHashN() {
        return N;
    }

    public int getHashR() {
        return r;
    }

    public int getHashP() {
        return p;
    }

    public int getHashLength() {
        return dkLen;
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "[N=" + N + ", r=" + r + ", p=" + p + ", salt=" + Base64.encode(passwordSalt) + "]";
    }
}
