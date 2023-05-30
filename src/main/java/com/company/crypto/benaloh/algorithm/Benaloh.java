package com.company.crypto.benaloh.algorithm;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;

import java.math.BigInteger;

public abstract class Benaloh {
    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OpenKey {
        private BigInteger y;
        private BigInteger r;
        private BigInteger n;
    }

    @Getter
    @RequiredArgsConstructor
    public static class PrivateKey {
        private final BigInteger f;
        private final BigInteger x;
    }

    public abstract byte[] encode(byte[] array, OpenKey openKey);
    public abstract byte[] decode(byte[] array);

    public abstract void regenerateOpenKey();
    public abstract OpenKey getOpenKey();
}
