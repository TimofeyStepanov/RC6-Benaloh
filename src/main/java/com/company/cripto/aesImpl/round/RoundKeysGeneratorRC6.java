package com.company.cripto.aesImpl.round;


/**
 * Generate all round keys
 **/
public interface RoundKeysGeneratorRC6 {
    int[] generate(byte[] cipherKey);
    int getWordLength();
}
