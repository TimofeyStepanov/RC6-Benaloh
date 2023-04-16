package com.company.cripto.aesImpl.round;


/**
 * Generate all round keys
 **/
public interface RoundKeysGenerator {
    byte[][] generate(byte[] cipherKey);
}
