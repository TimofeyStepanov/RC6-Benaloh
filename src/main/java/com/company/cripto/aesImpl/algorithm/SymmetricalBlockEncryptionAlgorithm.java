package com.company.cripto.aesImpl.algorithm;


/**
 * Gets open text or encoded text. Gets key generator and round transformer
 **/
public interface SymmetricalBlockEncryptionAlgorithm {
    byte[] decode(byte[] inputBlock);
    byte[] encode(byte[] inputBlock);
    void setKey(byte[] cipherKey);
    int getOpenTextBlockSizeInBytes();
}
