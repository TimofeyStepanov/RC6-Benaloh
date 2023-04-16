package com.company.cripto.aesImpl.round;


import java.math.BigInteger;

/**
 * Generate all round keys
 **/
public interface RoundKeysGenerator {
    int[] generate(byte[] cipherKey);
}
