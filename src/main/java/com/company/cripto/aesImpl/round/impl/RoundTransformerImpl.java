package com.company.cripto.aesImpl.round.impl;

import com.company.cripto.aesImpl.round.RoundTransformer;

public class RoundTransformerImpl implements RoundTransformer {
    @Override
    public byte[] encode(byte[] inputBlock, byte[] roundKey, boolean predicate) {
        return new byte[0];
    }

    @Override
    public byte[] decode(byte[] inputBlock, byte[] roundKey, boolean predicate) {
        return new byte[0];
    }
}
