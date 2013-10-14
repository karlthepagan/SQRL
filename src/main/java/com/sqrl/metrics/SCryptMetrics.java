package com.sqrl.metrics;

import com.lambdaworks.crypto.SCrypt;
import org.apache.commons.math.stat.descriptive.SummaryStatistics;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.*;

/**
 * Utility class which provides methods to predict SCrypt work factors for the current host (heuristic-based) and
 * given memory limits (provable).
 */
public class SCryptMetrics {
    private static final double LOG2 = Math.log(2);

    /*
     * r=1 invites pre-compute attacks on salsa20/8
     *
     * see [Percival] p10, Footnote 14.
     */
    private static final int MIN_R = 2;

    private final byte[] password;
    private byte[] salt;

    private List<SCryptCandidate> candidates = new ArrayList<SCryptCandidate>();
    private SummaryStatistics costStatistics = new SummaryStatistics();
    boolean saveSampleTiming = false;
    private long benchmarkRuntime = 0;

    public SCryptMetrics(Random rand) {
        password = new byte[8];
        rand.nextBytes(password);

        salt = new byte[8];
        rand.nextBytes(salt);
    }

    public static void main(String[] args) throws Exception {
        SCryptMetrics m = new SCryptMetrics(new SecureRandom());
        long time = System.currentTimeMillis();
        SCrypt.scrypt(m.password,m.salt,1<<17,2,645,32);
        System.out.println(System.currentTimeMillis() - time);
        m.benchmarkSCrypt(32*1024*1024);
//        int[] params = m.paramsForLowP(60,32*1024*1024);
        int[] params = m.paramsForTimeGivenMemory(60,32*1024*1024);
        System.out.println("try " + params[0] + " " + params[1] + " " + params[2]);
    }

    /**
     * system heuristic prioritizing low parallelization, less accurate
     */
    public int[] paramsForLowP(double timeSpec, int memorySpec) {
        if(candidates.isEmpty()) throw new IllegalStateException("no benchmark data present");

        timeSpec *= 1000000000; // 1 second

        // FUZZ FACTOR
        // as timeSpec grows prediction becomes more difficult
        timeSpec *= 1.25;

        SCryptCandidate[] candidatesN = getBestCandidatesForN(candidates);

        double bestCost = costStatistics.getMin();

        // estimate N to match memoryspec
        double targetNx = Math.log(memorySpec / 128) / LOG2;
        int outNx = (int)Math.floor(targetNx);

        double predictedCost = bestCost;
        if(outNx <= 0) {
            // TODO Log.warn
            System.out.println("no good candidates!");
            outNx = (int)Math.ceil(targetNx);
        } else {
            int predictNx = outNx;
            while(candidatesN[predictNx] == null) {
                predictNx--;
            }
            predictedCost = candidatesN[predictNx].cost;
        }

        int outR = MIN_R;

        long outTime = getTime(predictedCost,1 << outNx,outR,1);
        int outP = (int)Math.ceil(timeSpec / outTime);

        // each iteration of P has equal memory usage, so the cost is high when used concurrently
        // we must try to prevent r creeping up to satisfy performance if it will hurt overall performance
        while(outR > MIN_R && outP > 1) {
            outNx++;
            outR = memorySpec / ((1 << outNx) * 128);
            if(candidatesN[outNx] == null) {
                // TODO Log warn
                System.out.println("no sample for Nx " + outNx);
            } else {
                predictedCost = candidatesN[outNx].cost;
            }
            outTime = getTime(predictedCost,1 << outNx,outR,1);
            outP = (int)Math.ceil(timeSpec / outTime);
        }

        return new int[]{outNx,outR,outP};
    }

    /**
     * system heuristic. at low timespec fuzz factor could be eliminated
     */
    public int[] paramsForTimeGivenMemory(double timeSpec, int memorySpec) throws GeneralSecurityException {
        if(candidates.isEmpty()) throw new IllegalStateException("no benchmark data present");

        timeSpec *= 1000000000; // 1 second

        // FUZZ FACTOR
        // as timeSpec grows prediction becomes more difficult
        timeSpec *= 1.25;

        SCryptCandidate[] candidatesN = getBestCandidatesForN(candidates);

        double bestCost = costStatistics.getMin();

        // estimate N with R=1
        double targetNx = Math.log(timeSpec / (bestCost * 128)) / LOG2;
        int outNx = (int)Math.ceil(targetNx);
        while(outNx > 0 && candidatesN[outNx] == null) {
            outNx--;
        }
        double predictedCost = bestCost;
        if(outNx <= 0) {
            // TODO Log.warn
            System.out.println("no good candidates!");
            outNx = (int)Math.ceil(targetNx);
        } else {
            predictedCost = candidatesN[outNx].cost;
        }

        int outR = memorySpec / ((1 << outNx) * 128);

        int outP = 1;

        long outTime = Long.MAX_VALUE;
        outR++;
        do {
            if(outR >= MIN_R) {
                outR--;
            } else {
                outNx--;
                if(outTime < timeSpec) {
                    outR *= 2;
                } else {
                    outR++;
                }
            }
            outTime = getTime(predictedCost,1 << outNx,outR,1);
        } while(outR < MIN_R || outTime > 2 * timeSpec);

        outP = (int)Math.ceil(timeSpec / outTime);

        return new int[]{outNx,outR,outP};
    }

    private long getMemory(int Nx, int r, int p) {
        return 128l * (1 << Nx) * r;
    }

    public void benchmarkSCrypt(long maxMemory) throws GeneralSecurityException {
        candidates.clear();
        costStatistics.clear();

        long sampleMinTime = 10000000;
        long sampleMaxTime = 400000000;

        long time = benchmarkRuntime = System.nanoTime();

        // invocation warmup
        for(int i = 1 << 16; i >=0 ; --i) {
            SCrypt.scrypt(password, salt, 2, 1, 1, 32);
        }

        time = System.nanoTime() - time;

        int px = 5;

//        System.out.println("N x\tr x\tp x\ttime\ttime/memory");
        // target 2^31-1 memory usage
        nextN:
        for(int Nx = 4; Nx < 23; Nx++) {
            for(int rx = Math.max(0,8 - Nx); rx < 8; rx++) {
                int N = 1 << Nx;
                int r = 1 << rx;
                if(N > maxMemory / r / 128) {
                    continue nextN;
                }

                time = 0;
                int p = 0;

                double bestCost = costStatistics.getMin();
                if(bestCost < Double.POSITIVE_INFINITY) {
                    px++;
                    do {
                        px--;
                        if(px < 0) {
                            px = 0;
                            continue nextN;
                        }
                        p = 1 << px;
                    } while(getTime(bestCost,N,r,p) > sampleMaxTime);
                }
                long[] samples = new long[64];
                while(time < sampleMinTime) {
                    p = 1 << px;
                    time = System.nanoTime();
                    SCrypt.scrypt(password,salt,N,r,p,32);
                    time = System.nanoTime() - time;
                    samples[px] = time;
                    px++;
                }
                px--;
                double cost = getCost(time,N,r,p);
                costStatistics.addValue(cost);
                SCryptCandidate candidate = new SCryptCandidate(r,cost,Nx);
                if(saveSampleTiming) {
                    System.arraycopy(samples,0,candidate.samples,0,Math.min(samples.length,candidate.samples.length));
                }
                candidates.add(candidate);
                // TODO Log.debug
//                System.out.println(MessageFormat.format("{0}\t{1}\t{2}\t{3}\t{4}", Nx, rx, px, time, cost));
                px = Math.max(0,px-=2);
                // TODO callback to gui here?
                if(time > sampleMaxTime) {
                    continue nextN;
                }
            }
        }

        Collections.sort(candidates, new CostComparator());
        if(candidates.get(candidates.size()-1).cost < costStatistics.getMean()) {
            // TODO Log.warn
            System.out.println("not enough memory for confident benchmark");
        }
        cullSCryptCandidatesForCost(candidates,costStatistics,16);

        benchmarkRuntime = System.nanoTime() - benchmarkRuntime;
    }

    protected SCryptCandidate[] getBestCandidatesForN(List<SCryptCandidate> candidates) {
        SCryptCandidate[] result = new SCryptCandidate[64];

        for(SCryptCandidate c : candidates) {
            int nx = c.Nx;
            SCryptCandidate co = result[nx];
            if(co == null || co.cost > c.cost) {
                result[nx] = c;
            }
        }

        return result;
    }

    public static double getCost(long time, int N, int r, int p) {
        return  time/(128.0 * r * N * p);
    }

    public static long getTime(double cost, int N, int r, int p) {
        return (long)(cost * 128 * N * r * p);
    }

    protected double cullSCryptCandidatesForCost(List<SCryptCandidate> candidates, SummaryStatistics costStats, int midNx) {
        double stddev = costStats.getStandardDeviation();
        double cullMinimum = costStats.getMean() + stddev;
        double preferMinimum = costStats.getMean() - stddev;

        int candidateLimit = candidates.size() - 1;

        while (candidateLimit >= 0
                && (candidates.get(candidateLimit) == null
                    || candidates.get(candidateLimit).cullCost(cullMinimum))) {

            if(candidates.get(candidateLimit).Nx < midNx) {
                candidates.remove(candidateLimit);
            }
            candidateLimit--;
        }

        return preferMinimum;
    }
}
