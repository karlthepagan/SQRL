package com.sqrl.metrics;

import java.text.MessageFormat;

/**
 * Encapsulates params candidate data
 */
public class SCryptCandidate {
    public final byte Nx;
    public final short r;
    public final float cost;
    public final long[] samples;

    public SCryptCandidate(int r, double cost, int Nx) {
        if(Nx > Byte.MAX_VALUE) throw new IllegalArgumentException();
        if(r > Short.MAX_VALUE) throw new IllegalArgumentException();

        this.r = (short)r;
        this.cost = (float)cost;
        this.Nx = (byte)Nx;
        this.samples = new long[64];
    }

    public String toString() {
        return MessageFormat.format("N=2^{1} r={0} cost={2,number,0.#}",r,(int) Nx, cost);
    }

    public boolean cullCost(double cullMinimum) {
        return cost > cullMinimum;
    }
}
