package com.company.crypto.benaloh.algorithm;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.math.BigInteger;

public abstract class Benaloh {
    @Getter
    @RequiredArgsConstructor
    public static class OpenKey {
        private final BigInteger y;
        private final BigInteger r;
        private final BigInteger n;
    }

    @Getter
    @RequiredArgsConstructor
    protected static class PrivateKey {
        private final BigInteger f;
        private final BigInteger x;
    }

    public abstract byte[] encode(byte[] array, OpenKey openKey);
    public abstract byte[] decode(byte[] array);

    public abstract void regenerateOpenKey();
    public abstract OpenKey getOpenKey();
}
