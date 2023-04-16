package com.company.cripto.aesImpl.round.impl;

import com.company.cripto.aesImpl.round.RoundTransformer;

import java.math.BigInteger;

public class RoundTransformerImpl implements RoundTransformer {
    @Override
    public byte[] encode(byte[] inputBlock, BigInteger roundKey, boolean predicate) {
        return new byte[0];
    }

    @Override
    public byte[] decode(byte[] inputBlock, BigInteger roundKey, boolean predicate) {
        return new byte[0];
    }
}
