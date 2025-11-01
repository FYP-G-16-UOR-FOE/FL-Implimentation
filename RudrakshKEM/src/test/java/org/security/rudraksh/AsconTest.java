package org.security.rudraksh;

import org.bouncycastle.crypto.digests.AsconXof;
import org.junit.Test;
import static org.junit.Assert.*;

public class AsconTest {

    @Test
    public void testAsconXof() {
        // ✅ CORRECT: Use AsconXof (not ASCON_XOF128)
        AsconXof xof = new AsconXof(AsconXof.AsconParameters.AsconXof);

        // Input seed (like matrix generation seed in Rudraksh)
        byte[] seed = "test_seed_for_matrix_generation".getBytes();
        xof.update(seed, 0, seed.length);

        // Generate 64 bytes of pseudorandom output
        byte[] output = new byte[64];
        xof.doFinal(output, 0, output.length);

        // Verify output is not all zeros
        boolean hasNonZero = false;
        for (byte b : output) {
            if (b != 0) {
                hasNonZero = true;
                break;
            }
        }

        assertTrue("ASCON-XOF should produce non-zero output", hasNonZero);
        assertEquals("Output should be 64 bytes", 64, output.length);

        System.out.println("✅ ASCON-XOF test passed!");
        System.out.print("First 16 bytes: ");
        for (int i = 0; i < 16; i++) {
            System.out.printf("%02x ", output[i] & 0xff);
        }
        System.out.println();
    }
}
