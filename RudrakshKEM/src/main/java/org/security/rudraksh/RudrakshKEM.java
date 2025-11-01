// File: RudrakshKEM.java
package org.security.rudraksh;

import org.bouncycastle.crypto.digests.AsconXof;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Rudraksh KEM (KEM-poly64) — corrected, compilable implementation.
 * Assumes a correct Ntt7681.java in the same package with methods:
 *   - public void ntt(int[] a)  // in-place forward
 *   - public void invNtt(int[] a) // in-place inverse
 *
 * Notes:
 *  - This file focuses on fixing Java syntax/types and deterministic XOF usage.
 *  - You must ensure AsconXof usage matches the BouncyCastle version you use.
 */
public class RudrakshKEM {
    // Parameters (keep aligned with your choices)
    public static final int N = 64;
    public static final int L = 9;
    public static final int Q = 7681;
    public static final int B = 2;
    public static final int TWO_B = 2 * B;

    public static final int P_BITS = 10;
    public static final int P = 1 << P_BITS;                // 1024
    public static final int V_COMPRESS_P = 1 << 12 ; //1 << 12;  //1 << (3 + B) ;//1 << 12;         // 4096
    public static final int LEN_K_BITS = 128;
    public static final int LEN_K_BYTES = LEN_K_BITS / 8;   // 32

    public static final int SEED_BYTES = 32; // length for seedA / randomness

    private static final SecureRandom RNG = new SecureRandom();
    private static final boolean VERBOSE = true;

    private final Ntt7681 ntt;

    public RudrakshKEM() { this.ntt = new Ntt7681(N); }

    /* ---- Data structures ---- */
    public static class PkePk {
        public byte[] seedA = new byte[SEED_BYTES];
        public int[][][] A_hat = new int[L][L][N]; // stored in NTT domain
        public int[][] b_hat = new int[L][N];     // stored in NTT domain

        public PkePk() {
            for (int i = 0; i < L; i++) Arrays.fill(b_hat[i], 0);
        }
    }
    public static class PkeSk {
        public int[][] s_hat = new int[L][N]; // in NTT domain

        public PkeSk() { for (int i = 0; i < L; i++) Arrays.fill(s_hat[i], 0); }
    }
    public static class PkeCiphertext {
        public int[][] u = new int[L][N];
        public int[] v = new int[N];

        public PkeCiphertext() { for (int i = 0; i < L; i++) Arrays.fill(u[i], 0); Arrays.fill(v, 0); }
    }
    public static class KEMPk { public PkePk pkePk; }
    public static class KEMSk { public PkeSk pkeSk; public byte[] z = new byte[LEN_K_BYTES]; public byte[] pkh; }

    /* ---- Utilities ---- */
    private static void csprngBytes(byte[] out) { RNG.nextBytes(out); }

    private static int addQ(int a, int b) { int s = a + b; if (s >= Q) s -= Q; return s; }
    private static int subQ(int a, int b) { int d = a - b; if (d < 0) d += Q; return d; }

    private static void debug(String fmt, Object... args) { if (!VERBOSE) return; // System.out.printf(fmt + "%n", args);
    }
    private static void debugPolyFull(String label, int[] poly) { if (!VERBOSE) return;// System.out.printf("%s (len=%d): %s%n", label, poly.length, Arrays.toString(poly));
    }
    private static void debugMatrix(String label, int[][] mat) { if (!VERBOSE) return; //System.out.println(label + " (matrix):"); for (int i = 0; i < mat.length; i++) System.out.printf("  [%d]: %s%n", i, Arrays.toString(mat[i]));
    }
    private static void debugBytes(String label, byte[] b) { if (!VERBOSE) return; //System.out.printf("%s (len=%d): %s%n", label, b.length, bytesHex(b));
    }
    private static String bytesHex(byte[] b) { StringBuilder sb = new StringBuilder(); for (byte x : b) sb.append(String.format("%02x", x & 0xff)); return sb.toString(); }

    /* ---- Deterministic Ascon XOF stream wrapper ----
       Reason: ensure identical squeeze sequences regardless of chunk sizes.
       NOTE: The AsconXof methods used here assume:
         - update(byte[] in, int off, int len)
         - doFinal(byte[] out, int off, int outLen)
       If your BouncyCastle version differs, adapt accordingly.
    */
    private static final class AsconXofStream {
        private final AsconXof xof;
        private byte[] buffer;   // internal buffer produced by doFinal
        private int pos;

        AsconXofStream() {
            this.xof = new AsconXof(AsconXof.AsconParameters.AsconXof);
            this.buffer = new byte[0];
            this.pos = 0;
        }

        void absorb(byte[] input) {
            if (input == null || input.length == 0) return;
            xof.update(input, 0, input.length);
        }

        // Ensure we have at least 'want' more bytes available in buffer (from pos)
        private void ensureBuffer(int want) {
            if (buffer != null && (buffer.length - pos) >= want) return;
            // request a reasonably large chunk
            int chunk = Math.max(4096, want);
            buffer = new byte[chunk];
            // note: some AsconXof APIs expect doFinal(out, outOff, outLen)
            xof.doFinal(buffer, 0, buffer.length);
            pos = 0;
            // After doFinal, the XOF state is finished. If you need continuous squeezes,
            // you should re-initialize or use a streaming XOF API if available.
            // For deterministic behavior we create a fresh AsconXof per use where required.
        }

        void squeeze(byte[] out) {
            if (out == null || out.length == 0) return;
            ensureBuffer(out.length);
            System.arraycopy(buffer, pos, out, 0, out.length);
            pos += out.length;
        }

        static byte[] hash(byte[] input, int outLen) {
            AsconXofStream s = new AsconXofStream();
            s.absorb(input);
            byte[] out = new byte[outLen];
            s.squeeze(out);
            return out;
        }
    }

    /* ---- Bit reader for rejection sampling ---- */
    private static final class XofBitReader {
        private final AsconXofStream stream;
        private long buffer = 0L;
        private int bitsAvailable = 0;

        XofBitReader(AsconXofStream s) { this.stream = s; }

        private void refillIfNeeded() {
            if (bitsAvailable >= 32) return; // keep at least 32 bits buffered
            byte[] tmp = new byte[8];
            stream.squeeze(tmp);
            long newBits = 0L;
            for (int i = 0; i < 8; i++) newBits |= ((long)(tmp[i] & 0xFF)) << (8 * i);
            buffer |= (newBits << bitsAvailable);
            bitsAvailable += 64;
        }

        int next13Bits() {
            while (bitsAvailable < 13) refillIfNeeded();
            int res = (int)(buffer & 0x1FFF); // 13 bits
            buffer >>>= 13;
            bitsAvailable -= 13;
            return res;
        }

        // get n bits (n <= 32)
        int nextBits(int n) {
            if (n <= 0 || n > 32) throw new IllegalArgumentException("n must be 1..32");
            while (bitsAvailable < n) refillIfNeeded();
            int res = (int)(buffer & ((1L << n) - 1));
            buffer >>>= n;
            bitsAvailable -= n;
            return res;
        }
    }
    private static int[] messageBytesToPoly2B(byte[] m) {
        int[] out = new int[N];
        int bitPos = 0;
        for (int i = 0; i < N; i++) {
            int val = 0;
            for (int b = 0; b < B; b++) {  // B bits, not TWO_B!
                int byteIndex = (bitPos + b) / 8;
                int bitIndex  = (bitPos + b) % 8;
                int bit = 0;
                if (byteIndex < m.length) bit = (m[byteIndex] >>> bitIndex) & 1;
                val |= (bit << b);
            }
            out[i] = val & ((1 << B) - 1);  // Mask to B bits
            bitPos += B;  // Advance by B bits
        }
        return out;
    }
    private static byte[] poly2BToMessageBytes(int[] poly) {
        int totalBits = N * B;  // B bits per coefficient
        int outLen = (totalBits + 7) / 8;
        byte[] out = new byte[outLen];
        int bitPos = 0;
        for (int i = 0; i < N; i++) {
            int coeff = poly[i] & ((1 << B) - 1);  // Mask to B bits
            for (int b = 0; b < B; b++) {  // B bits
                int bit = (coeff >> b) & 1;
                int byteIndex = (bitPos + b) / 8;
                int bitIndex  = (bitPos + b) % 8;
                if (byteIndex < out.length) out[byteIndex] |= (bit << bitIndex);
            }
            bitPos += B;
        }
        return out;
    }

    private static int[] encodeMessagePoly(int[] mPoly) {
        int[] out = new int[N];
        // Paper: Encode(m) = ⌊q/2^B⌉ × m
        for (int i = 0; i < N; i++) {
            int coeff = mPoly[i] & ((1 << B) - 1);  // B-bit value (0-3)
            // Compute ⌊q/2^B⌉ with rounding: (Q + 2^(B-1)) >> B
            out[i] = (int)(((long)Q * coeff + (1L << (B - 1))) >> B);
        }
        return out;
    }
    private static int[] decodeMessagePoly(int[] polyQ) {
        int[] out = new int[N];
        // Paper: Decode(m'') = ⌊(2^B × m'' + ⌊q/2⌉) / q⌋ & (2^B - 1)
        for (int i = 0; i < N; i++) {
            long tmp = (((long)(1 << B)) * polyQ[i] + (Q / 2L));
            out[i] = (int)((tmp / Q) & ((1 << B) - 1));
        }
        return out;
    }

    private static int compressCoeff(int coeff, int p) {
        long num = (long) coeff * p + Q / 2L;
        return (int) ((num / Q) % p);
    }
    private static int decompressCoeff(int u, int p) {
        long num = (long) Q * u + (p / 2L);
        return (int) (num / p);
    }

    private static void sampleVectorCBD(int[][] outVec, byte[] seed, byte domain) {
        for (int i = 0; i < L; i++) {
            AsconXofStream s = new AsconXofStream();
            byte[] sPlus = Arrays.copyOf(seed, seed.length + 2);
            sPlus[sPlus.length - 2] = domain;
            sPlus[sPlus.length - 1] = (byte) i;
            s.absorb(sPlus);
            XofBitReader br = new XofBitReader(s);
            for (int j = 0; j < N; j++) {
                int u = br.nextBits(2);
                int v = br.nextBits(2);
                outVec[i][j] = Integer.bitCount(u) - Integer.bitCount(v);
            }
        }
    }

    /* ---- Generate A_hat from seed (NTT domain) ---- */
    private void generateAhatFromSeed(PkePk pk) {
        final int MAX_ATTEMPTS = 16384;
        debugBytes("seedA (generateAhatFromSeed)", pk.seedA);
        for (int row = 0; row < L; row++) {
            for (int col = 0; col < L; col++) {
                AsconXofStream s = new AsconXofStream();
                byte[] seedPlus = Arrays.copyOf(pk.seedA, pk.seedA.length + 2);
                seedPlus[seedPlus.length - 2] = (byte) row;
                seedPlus[seedPlus.length - 1] = (byte) col;
                s.absorb(seedPlus);
                XofBitReader xs = new XofBitReader(s);
                int[] poly = new int[N];
                int idx = 0;
                int attempts = 0;
                while (idx < N) {
                    if (++attempts > MAX_ATTEMPTS) throw new IllegalStateException("too many rejections for A");
                    int cand = xs.next13Bits();
                    if (cand < Q) poly[idx++] = cand;
                }
                debugPolyFull(String.format("A_hat[%d][%d] (coeff, before NTT)", row, col), poly);
                ntt.ntt(poly);
                debugPolyFull(String.format("A_hat[%d][%d] (NTT stored)", row, col), poly);
                pk.A_hat[row][col] = poly;
            }
        }
    }

    /* ---- PKE KeyGen ---- */
    public void pkeKeyGen(PkePk pk, PkeSk sk) {
        csprngBytes(pk.seedA);
        debugBytes("seedA (pkeKeyGen)", pk.seedA);
        generateAhatFromSeed(pk);

        byte[] seedSE = new byte[SEED_BYTES];
        csprngBytes(seedSE);
        debugBytes("seedSE", seedSE);

        int[][] s = new int[L][N];
        int[][] e = new int[L][N];
        sampleVectorCBD(s, seedSE, (byte) 0x00);
        sampleVectorCBD(e, seedSE, (byte) 0x01);
        debugMatrix("s (coeff)", s);
        debugMatrix("e (coeff)", e);

        int[][] s_hat = new int[L][N];
        int[][] e_hat = new int[L][N];

        for (int i = 0; i < L; i++) {
            for (int k = 0; k < N; k++) {
                s_hat[i][k] = ((s[i][k] % Q) + Q) % Q;
                e_hat[i][k] = ((e[i][k] % Q) + Q) % Q;
            }
            ntt.ntt(s_hat[i]);
            ntt.ntt(e_hat[i]);
            debugPolyFull("s_hat[" + i + "] (NTT)", s_hat[i]);
            debugPolyFull("e_hat[" + i + "] (NTT)", e_hat[i]);
            System.arraycopy(s_hat[i], 0, sk.s_hat[i], 0, N);
        }

        // compute b_hat = A_hat * s_hat + e_hat (in NTT domain)
        for (int i = 0; i < L; i++) {
            int[] acc = new int[N];
            Arrays.fill(acc, 0);
            for (int j = 0; j < L; j++) {
                int[] aij = pk.A_hat[i][j];
                int[] sj = s_hat[j];
                for (int k = 0; k < N; k++) acc[k] = (acc[k] + (int)(((long)aij[k] * sj[k]) % Q)) % Q;
                debugPolyFull(String.format("acc after A[%d][%d]*s_hat[%d]", i, j, j), acc);
            }
            for (int k = 0; k < N; k++) pk.b_hat[i][k] = addQ(acc[k], e_hat[i][k]);
            debugPolyFull("b_hat[" + i + "] (NTT)", pk.b_hat[i]);
        }
    }

    /* ---- PKE Encapsulation ---- */
    public PkeCiphertext pkeEnc(PkePk pk, byte[] m, byte[] rSeed) {
        if (rSeed == null) { rSeed = new byte[SEED_BYTES]; csprngBytes(rSeed); }
        debugBytes("Message (enc) m", m);
        debugBytes("rSeed (enc)", rSeed);

        int[][] sprime = new int[L][N];
        int[][] eprime = new int[L][N];
        int[] edd = new int[N];

        sampleVectorCBD(sprime, rSeed, (byte)0x00);
        sampleVectorCBD(eprime, rSeed, (byte)0x01);
        debugMatrix("sprime (coeff)", sprime);
        debugMatrix("eprime (coeff)", eprime);

        // e'' sampling (use independent 2-bit draws per coefficient)
        {
            AsconXofStream s = new AsconXofStream();
            byte[] splus = Arrays.copyOf(rSeed, rSeed.length + 1);
            splus[splus.length - 1] = (byte)0x02;
            s.absorb(splus);
            XofBitReader br = new XofBitReader(s);
            for (int j = 0; j < N; j++) {
                int u = br.nextBits(2);
                int v = br.nextBits(2);
                edd[j] = Integer.bitCount(u) - Integer.bitCount(v);
            }
            debugPolyFull("e'' (coeff edd)", edd);
        }

        // sprime_hat
        int[][] sprime_hat = new int[L][N];
        for (int i = 0; i < L; i++) {
            for (int k = 0; k < N; k++) sprime_hat[i][k] = ((sprime[i][k] % Q) + Q) % Q;
            ntt.ntt(sprime_hat[i]);
            debugPolyFull("sprime_hat[" + i + "] (NTT)", sprime_hat[i]);
        }

        // u component: bPrime = INTT( A^T * sprime_hat ) + eprime (in coefficient domain -> compress)
        int[][] bPrime = new int[L][N];
        for (int i = 0; i < L; i++) {
            int[] acc = new int[N];
            Arrays.fill(acc, 0);
            for (int j = 0; j < L; j++) {
                int[] aji = pk.A_hat[j][i]; // A^T element in NTT domain
                int[] sjHat = sprime_hat[j];
                for (int k = 0; k < N; k++) acc[k] = (acc[k] + (int)(((long)aji[k] * sjHat[k]) % Q)) % Q;
                debugPolyFull(String.format("bhatPrime acc (j=%d,i=%d)", j, i), acc);
            }
            // acc is in NTT domain; bring to coefficient domain
            System.arraycopy(acc, 0, bPrime[i], 0, N);
            ntt.invNtt(bPrime[i]);
            debugPolyFull("bPrime (after INTT, before e')", bPrime[i]);
            for (int k = 0; k < N; k++) bPrime[i][k] = addQ(bPrime[i][k], ((eprime[i][k] % Q) + Q) % Q);
            debugPolyFull("bPrime (after add e')", bPrime[i]);
        }

        PkeCiphertext ct = new PkeCiphertext();
        for (int i = 0; i < L; i++) for (int k = 0; k < N; k++) ct.u[i][k] = compressCoeff(bPrime[i][k], P);
        debugMatrix("u (compressed)", ct.u);

        // v component
        int[] cHatm = new int[N];
        Arrays.fill(cHatm, 0);
        for (int i = 0; i < L; i++) {
            int[] biHat = pk.b_hat[i];
            int[] sPHat = sprime_hat[i];
            for (int k = 0; k < N; k++) cHatm[k] = (cHatm[k] + (int)(((long)biHat[k] * sPHat[k]) % Q)) % Q;
            debugPolyFull(String.format("cHatm after i=%d", i), cHatm);
        }
        debugPolyFull("cHatm (NTT)", cHatm);

        int[] cm = Arrays.copyOf(cHatm, N);
        ntt.invNtt(cm);
        debugPolyFull("cm (after INTT, before e''+m)", cm);

        for (int k = 0; k < N; k++) cm[k] = addQ(cm[k], ((edd[k] % Q) + Q) % Q);
        debugPolyFull("cm (after add e'')", cm);

        int[] mPoly2B = messageBytesToPoly2B(m);
        debugPolyFull("mPoly2B (message -> 2B)", mPoly2B);

        int[] encoded = encodeMessagePoly(mPoly2B);
        debugPolyFull("encoded(m) (Q domain)", encoded);

        for (int k = 0; k < N; k++) cm[k] = addQ(cm[k], encoded[k]);
        debugPolyFull("cm (before compress final)", cm);

        for (int k = 0; k < N; k++) ct.v[k] = compressCoeff(cm[k], V_COMPRESS_P);
        debugPolyFull("v (compressed)", ct.v);

        return ct;
    }

    /* ---- PKE Decapsulation ---- */
    public byte[] pkeDec(PkeSk sk, PkeCiphertext ct) {
        int[][] uPrime = new int[L][N];
        for (int i = 0; i < L; i++) for (int k = 0; k < N; k++) uPrime[i][k] = decompressCoeff(ct.u[i][k], P);
        int[] vPrime = new int[N];
        for (int k = 0; k < N; k++) vPrime[k] = decompressCoeff(ct.v[k], V_COMPRESS_P);

        debugMatrix("uPrime (decompressed)", uPrime);
        debugPolyFull("vPrime (decompressed)", vPrime);

        int[][] uHatPrime = new int[L][N];
        for (int i = 0; i < L; i++) {
            System.arraycopy(uPrime[i], 0, uHatPrime[i], 0, N);
            ntt.ntt(uHatPrime[i]);
            debugPolyFull("uHatPrime[" + i + "] (NTT)", uHatPrime[i]);
        }

        int[] uHatDouble = new int[N];
        Arrays.fill(uHatDouble, 0);
        for (int i = 0; i < L; i++) {
            int[] uHi = uHatPrime[i];
            int[] sHi = sk.s_hat[i];
            for (int k = 0; k < N; k++) uHatDouble[k] = (uHatDouble[k] + (int)(((long)uHi[k] * sHi[k]) % Q)) % Q;
        }
        debugPolyFull("uHatDouble (NTT)", uHatDouble);

        int[] tmp = Arrays.copyOf(uHatDouble, N);
        ntt.invNtt(tmp);
        debugPolyFull("tmp (after INTT)", tmp);

        int[] mDblPrime = new int[N];
        for (int k = 0; k < N; k++) mDblPrime[k] = subQ(vPrime[k], tmp[k]);
        debugPolyFull("mDblPrime (v' - INTT(uHatDouble))", mDblPrime);

        int[] mPoly2B = decodeMessagePoly(mDblPrime);
        debugPolyFull("mPoly2B (decoded 2B)", mPoly2B);

        byte[] msg = poly2BToMessageBytes(mPoly2B);
        debugBytes("recovered message (decoded)", msg);
        return msg;
    }

    /* ---- FO KEM primitives ---- */
    private static byte[] G_function(byte[] pkh, byte[] m) {
        // produce 2*LEN_K_BYTES output, split into K and r
        AsconXofStream g = new AsconXofStream();
        byte[] input = new byte[(pkh != null ? pkh.length : 0) + (m != null ? m.length : 0)];
        if (pkh != null) System.arraycopy(pkh, 0, input, 0, pkh.length);
        if (m != null) System.arraycopy(m, 0, input, pkh.length, m.length);
        g.absorb(input);
        return AsconXofStream.hash(input, LEN_K_BYTES * 2);
    }
    private static byte[] H_function(byte[] input) { return AsconXofStream.hash(input, LEN_K_BYTES); }

    /* ---- Serialization helpers ---- */
    private static byte[] serializePk(PkePk pk) {
        int total = pk.seedA.length + L * N * 2; // seedA + b_hat (each coeff 2 bytes)
        byte[] out = new byte[total];
        int pos = 0;
        System.arraycopy(pk.seedA, 0, out, pos, pk.seedA.length);
        pos += pk.seedA.length;
        for (int i = 0; i < L; i++) for (int k = 0; k < N; k++) {
            int val = pk.b_hat[i][k] & 0xFFFF;
            out[pos++] = (byte)(val & 0xFF);
            out[pos++] = (byte)((val >>> 8) & 0xFF);
        }
        return out;
    }
    private static byte[] serializeCiphertext(PkeCiphertext ct) {
        int total = (L * N + N) * 2;
        byte[] out = new byte[total];
        int pos = 0;
        for (int i = 0; i < L; i++) for (int k = 0; k < N; k++) {
            int val = ct.u[i][k] & 0xFFFF;
            out[pos++] = (byte)(val & 0xFF);
            out[pos++] = (byte)((val >>> 8) & 0xFF);
        }
        for (int k = 0; k < N; k++) {
            int val = ct.v[k] & 0xFFFF;
            out[pos++] = (byte)(val & 0xFF);
            out[pos++] = (byte)((val >>> 8) & 0xFF);
        }
        return out;
    }
    private static PkeCiphertext deserializeCiphertext(byte[] ser) {
        PkeCiphertext ct = new PkeCiphertext();
        int pos = 0;
        for (int i = 0; i < L; i++) for (int k = 0; k < N; k++) {
            int lo = ser[pos++] & 0xFF;
            int hi = ser[pos++] & 0xFF;
            ct.u[i][k] = (hi << 8) | lo;
        }
        for (int k = 0; k < N; k++) {
            int lo = ser[pos++] & 0xFF;
            int hi = ser[pos++] & 0xFF;
            ct.v[k] = (hi << 8) | lo;
        }
        return ct;
    }

    /* ---- KEM API ---- */
    public void kemKeyGen(KEMPk outPk, KEMSk outSk) {
        outPk.pkePk = new PkePk();
        outSk.pkeSk = new PkeSk();
        pkeKeyGen(outPk.pkePk, outSk.pkeSk);
        outSk.pkh = H_function(serializePk(outPk.pkePk));
        csprngBytes(outSk.z);
        debugBytes("pkh", outSk.pkh);
        debugBytes("z (sk)", outSk.z);
    }

    public byte[][] kemEncaps(KEMPk pkObj) {
        byte[] m = new byte[(N * B + 7) / 8]; // enough bytes for message encoding
        csprngBytes(m);
        byte[] pkh = H_function(serializePk(pkObj.pkePk));
        byte[] kr = G_function(pkh, m);
        debugBytes("kemEncaps.m", m);
        byte[] k = Arrays.copyOfRange(kr, 0, LEN_K_BYTES);
        byte[] r = Arrays.copyOfRange(kr, LEN_K_BYTES, LEN_K_BYTES * 2);

        PkeCiphertext ct = pkeEnc(pkObj.pkePk, m, r);
        byte[] ser = serializeCiphertext(ct);
        debugBytes("kemEncaps.ct(serialized)", ser);
        // return concatenation <ct||K>
        // Final shared secret = H(ct || k)
        byte[] cAndK = new byte[ser.length + k.length];
        System.arraycopy(ser, 0, cAndK, 0, ser.length);
        System.arraycopy(k, 0, cAndK, ser.length, k.length);
        byte[] K = H_function(cAndK);

        return new byte[][]{ser, K}; // return ct and shared K separately
    }

    public byte[] kemDecaps(KEMPk pkObj, KEMSk skObj, byte[] ctSerializedAndK) {
        // input is <ct||K> or sometimes only ct; handle both forms
        if (ctSerializedAndK == null) return null;
        int ctLen = (L * N + N) * 2;
        if (ctSerializedAndK.length < ctLen) throw new IllegalArgumentException("malformed input");
        byte[] ctSerialized = Arrays.copyOfRange(ctSerializedAndK, 0, ctLen);
        byte[] Kenc = null;
        if (ctSerializedAndK.length >= ctLen + LEN_K_BYTES) {
            Kenc = Arrays.copyOfRange(ctSerializedAndK, ctLen, ctLen + LEN_K_BYTES);
        }


        PkeCiphertext ct = deserializeCiphertext(ctSerialized);
        byte[] mPrime = pkeDec(skObj.pkeSk, ct);

        byte[] kr = G_function(skObj.pkh, mPrime);
        byte[] Kprime = Arrays.copyOfRange(kr, 0, LEN_K_BYTES);
        byte[] rprime = Arrays.copyOfRange(kr, LEN_K_BYTES, LEN_K_BYTES * 2);

        PkeCiphertext cStar = pkeEnc(pkObj.pkePk, mPrime, rprime);
        byte[] cStarSer = serializeCiphertext(cStar);
        // Candidate 1: success path
        byte[] cAndK = new byte[ctSerialized.length + Kprime.length];
        System.arraycopy(ctSerialized, 0, cAndK, 0, ctSerialized.length);
        System.arraycopy(Kprime, 0, cAndK, ctSerialized.length, Kprime.length);
        byte[] Ksuccess = H_function(cAndK);

        // Candidate 2: failure path
        byte[] cAndZ = new byte[ctSerialized.length + skObj.z.length];
        System.arraycopy(ctSerialized, 0, cAndZ, 0, ctSerialized.length);
        System.arraycopy(skObj.z, 0, cAndZ, ctSerialized.length, skObj.z.length);
        byte[] Kfail = H_function(cAndZ);

        // Choose depending on ciphertext equality
        boolean equal = Arrays.equals(ctSerialized, cStarSer);
        return equal ? Ksuccess : Kfail;

    }

    /* ---- Main demo ---- */
    public static void main(String[] args) {
        System.out.println("Rudraksh KEM debug build (fixed).");
        RudrakshKEM impl = new RudrakshKEM();
        KEMPk pk = new KEMPk();
        KEMSk sk = new KEMSk();
        try { impl.kemKeyGen(pk, sk); } catch (Exception ex) { ex.printStackTrace(); System.err.println("KeyGen failed."); return; }

        // PKE unit test
        byte[] m = new byte[(N * B + 7) / 8];
        csprngBytes(m);
        byte[] r = new byte[LEN_K_BYTES];
        csprngBytes(r);
        PkeCiphertext ct = impl.pkeEnc(pk.pkePk, m, r);
        byte[] mprime = impl.pkeDec(sk.pkeSk, ct);
        System.out.println("PKE enc/dec equality? " + Arrays.equals(m, mprime));
        if (!Arrays.equals(m, mprime)) { debugBytes("m", m); debugBytes("m'", mprime); }

        // Run KEM test 100 times
        int trials = 1000;
        int failures = 0;
        for (int i = 0; i < trials; i++) {
            byte[][] ctAndK = impl.kemEncaps(pk);
            byte[] ctSer = ctAndK[0];
            byte[] Kenc  = ctAndK[1];

            byte[] Kdec = impl.kemDecaps(pk, sk, ctSer);

            boolean match = Arrays.equals(Kenc, Kdec);

            System.out.printf("cypher text length: %d%n", ctSer.length);
            System.out.printf("shared key length: %d%n", Kenc.length);
            if (!match) {

                System.out.printf("Trial %d: MISMATCH%n", i);
                byte[] Kdec2 = impl.kemDecaps(pk, sk, ctSer);

                boolean match2 = Arrays.equals(Kenc, Kdec2);
                if (!match2) {
                    failures++;
                    System.out.printf("Trial %d: MISMATCH 2 %n", i/10);
                }
            }
        }

        System.out.printf("Total trials: %d, Failures: %d%n", trials, failures);
        System.out.printf("Failure rate: %.2f%%%n", (failures * 100.0) / trials);
    }
}
