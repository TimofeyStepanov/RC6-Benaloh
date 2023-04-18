package com.company.crypto.aesImpl.round;


/**
 * Generate all round keys
 **/
public interface RoundKeysGenerator32BitsRC6 {
    int[] generate(byte[] cipherKey);
    int getWordLength();
}
