package com.company.cripto.aesImpl.round;


/**
 * Makes one round of symmetric algorithm
 **/
public interface  RoundTransformer {
    byte[] encode(byte[] inputBlock, byte[] roundKey, boolean predicate);
    byte[] decode(byte[] inputBlock, byte[] roundKey, boolean predicate);
}