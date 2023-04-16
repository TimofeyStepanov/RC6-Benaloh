package com.company.cripto.aesImpl.round;


import java.math.BigInteger;

/**
 * Generate all round keys
 **/
public interface RoundKeysGenerator {
    BigInteger[] generate(byte[] cipherKey);
}
