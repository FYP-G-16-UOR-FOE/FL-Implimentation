// File: Ntt7681.java
package org.security.rudraksh;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

/**
 * In-place radix-2 negacyclic NTT for q=7681, general power-of-two N.
 * Forward:  pre-multiply by ζ^j, bit-rev, Cooley-Tukey DIT using ω
 * Inverse: inverse Cooley-Tukey (using ω^{-1}), bit-rev, post-multiply by ζ^{-j} and invN
 *
 * Methods: ntt(int[] a) and invNtt(int[] a) operate in-place on length-N arrays.
 */
public final class Ntt7681 {
    public static final int Q = 7681;
    private final int N;
    private final int logN;
    private final int[] zetaPow;    // ζ^j, j=0..N-1  (ζ primitive 2N-th root)
    private final int[] invZetaPow; // ζ^{-j}
    private final int omega;        // ω = ζ^2 (primitive N-th root)
    private final int invN;

    public Ntt7681(int N) {
        if (Integer.bitCount(N) != 1) throw new IllegalArgumentException("N must be power of two");
        if ((Q - 1) % (2 * N) != 0) throw new IllegalArgumentException("Require 2N | Q-1 for primitive 2N-th root");
        this.N = N;
        this.logN = Integer.numberOfTrailingZeros(N);
        int g = findPrimitiveRoot(Q);
        int zeta = powMod(g, (Q - 1) / (2 * N), Q); // primitive 2N-th root ζ
        this.omega = powMod(zeta, 2, Q);             // primitive N-th root ω = ζ^2

        this.zetaPow = new int[N];
        this.invZetaPow = new int[N];
        long cur = 1;
        for (int j = 0; j < N; j++) {
            zetaPow[j] = (int) cur;
            invZetaPow[j] = powMod(zetaPow[j], Q - 2, Q);
            cur = (cur * zeta) % Q;
        }

        this.invN = powMod(N, Q - 2, Q);
    }

    /** Forward in-place NTT implementing Rudraksh Eq.(1) */
    public void ntt(int[] a) {
        if (a.length != N) throw new IllegalArgumentException("poly length mismatch");
        // pre-multiply by ζ^j
        for (int j = 0; j < N; j++) a[j] = mulMod(a[j], zetaPow[j]);

        // bit-reverse permutation
        bitReverseInPlace(a);

        // Cooley-Tukey DIT iterative
        for (int len = 2; len <= N; len <<= 1) {
            int half = len >> 1;
            int wlen = powMod(omega, N / len, Q); // ω^{N/len}
            for (int i = 0; i < N; i += len) {
                int w = 1;
                for (int j = 0; j < half; j++) {
                    int u = a[i + j];
                    int v = mulMod(a[i + j + half], w);
                    int x = u + v; if (x >= Q) x -= Q;
                    int y = u - v; if (y < 0) y += Q;
                    a[i + j] = x;
                    a[i + j + half] = y;
                    w = mulMod(w, wlen);
                }
            }
        }
    }

    /** In-place inverse NTT implementing Rudraksh Eq.(2) */
    public void invNtt(int[] a) {
        if (a.length != N) throw new IllegalArgumentException("poly length mismatch");
        // inverse Cooley-Tukey DIT: use wlen_inv = (ω^{N/len})^{-1}
        for (int len = N; len >= 2; len >>= 1) {
            int half = len >> 1;
            int wlen = powMod(omega, N / len, Q);
            int wlenInv = powMod(wlen, Q - 2, Q);
            for (int i = 0; i < N; i += len) {
                int w = 1;
                for (int j = 0; j < half; j++) {
                    int u = a[i + j];
                    int v = a[i + j + half];
                    int x = u + v; if (x >= Q) x -= Q;
                    int y = u - v; if (y < 0) y += Q;
                    a[i + j] = x;
                    a[i + j + half] = mulMod(y, w);
                    w = mulMod(w, wlenInv);
                }
            }
        }

        // bit-reverse to undo forward bit-reverse
        bitReverseInPlace(a);

        // post-multiply by ζ^{-j} and invN
        for (int j = 0; j < N; j++) {
            a[j] = mulMod(mulMod(a[j], invZetaPow[j]), invN);
        }
    }

    /* ---------------- helpers ---------------- */

    private void bitReverseInPlace(int[] a) {
        for (int i = 0; i < N; i++) {
            int j = Integer.reverse(i) >>> (32 - logN);
            if (j > i) { int tmp = a[i]; a[i] = a[j]; a[j] = tmp; }
        }
    }

    private static int mulMod(int x, int y) {
        return (int)((long)x * y % Q);
    }

    private static int powMod(int base, long exp, int mod) {
        long r = 1, b = base % mod;
        long e = exp;
        while (e > 0) {
            if ((e & 1) == 1) r = (r * b) % mod;
            b = (b * b) % mod;
            e >>= 1;
        }
        return (int) r;
    }

    private static int findPrimitiveRoot(int mod) {
        int phi = mod - 1;
        List<Integer> factors = new ArrayList<>();
        int t = phi;
        for (int p = 2; p * p <= t; p++) {
            if (t % p == 0) {
                factors.add(p);
                while (t % p == 0) t /= p;
            }
        }
        if (t > 1) factors.add(t);
        for (int g = 2; g < mod; g++) {
            boolean ok = true;
            for (int f : factors) {
                if (powMod(g, phi / f, mod) == 1) { ok = false; break; }
            }
            if (ok) return g;
        }
        throw new RuntimeException("no primitive root");
    }

    /* ---------- naive negacyclic for verification ---------- */
    public static int[] naiveNegacyclic(final int[] a, final int[] b) {
        int N = a.length;
        long[] tmp = new long[2 * N];
        for (int i = 0; i < N; i++) for (int j = 0; j < N; j++) tmp[i + j] += (long)a[i] * b[j];
        int[] res = new int[N];
        for (int i = 0; i < N; i++) {
            long v = tmp[i];
            for (int t = 1; i + t * N < tmp.length; t++) {
                if ((t & 1) == 1) v -= tmp[i + t * N]; else v += tmp[i + t * N];
            }
            res[i] = (int)((v % Q + Q) % Q);
        }
        return res;
    }

    /* ---------- self-test ---------- */
    public static void main(String[] args) {
        final int N_TEST = 64;
        Ntt7681 ntt = new Ntt7681(N_TEST);
        SecureRandom rnd = new SecureRandom();
        int[] a = new int[N_TEST], b = new int[N_TEST];
        for (int i = 0; i < N_TEST; i++) { a[i] = rnd.nextInt(Q); b[i] = rnd.nextInt(Q); }

        int[] ac = Arrays.copyOf(a, N_TEST), bc = Arrays.copyOf(b, N_TEST);
        ntt.ntt(ac); ntt.ntt(bc);
        // pointwise multiply in NTT domain
        int[] hc = new int[N_TEST];
        for (int i = 0; i < N_TEST; i++) hc[i] = (int)((long)ac[i] * bc[i] % Q);
        ntt.invNtt(hc);
        int[] naive = naiveNegacyclic(a, b);

        boolean ok = Arrays.equals(hc, naive);
        System.out.println("NTT multiplication correctness check: Equal? " + ok);
        if (!ok) {
            System.out.println("NTT result:   " + Arrays.toString(hc));
            System.out.println("Naive result: " + Arrays.toString(naive));
        }
    }
}
