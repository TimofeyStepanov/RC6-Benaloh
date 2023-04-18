package com.company.crypto.aesImpl.mode.fabric.impl;


import com.company.crypto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.crypto.aesImpl.mode.SymmetricalBlockModeCypher;
import com.company.crypto.aesImpl.mode.fabric.SymmetricalBlockCypherFabric;
import com.company.crypto.aesImpl.mode.impl.ECBCypher;

import java.util.Objects;

public class ECBFabric extends SymmetricalBlockCypherFabric {
    @Override
    public SymmetricalBlockModeCypher create(
            SymmetricalBlockEncryptionAlgorithm algorithm,
            Object... args) {
        Objects.requireNonNull(algorithm);

        return new ECBCypher(algorithm);
    }
}
