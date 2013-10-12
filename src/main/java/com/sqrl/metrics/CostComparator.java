package com.sqrl.metrics;

import java.util.Comparator;

/**
 * Ranks candidates so that the most efficient cost comes first. Nulls will move to the end.
 */
public class CostComparator implements Comparator<SCryptCandidate> {
    @Override
    public int compare(SCryptCandidate o1, SCryptCandidate o2) {
        if(o1 == o2) return 0;
        if(o1 == null) return 1;
        if(o2 == null) return -1;

        return Double.compare(o1.cost, o2.cost);
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof CostComparator;
    }
}
