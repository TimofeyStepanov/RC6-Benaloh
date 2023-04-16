package com.company.cripto.aesImpl.round;


import java.math.BigInteger;

/**
 * Makes one round of symmetric algorithm
 **/
public interface  RoundTransformer {
    byte[] encode(byte[] inputBlock, BigInteger roundKey, boolean predicate);
    byte[] decode(byte[] inputBlock, BigInteger roundKey, boolean predicate);
}