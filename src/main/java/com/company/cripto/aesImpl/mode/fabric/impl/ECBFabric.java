package com.company.cripto.aesImpl.mode.fabric.impl;


import com.company.cripto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.cripto.aesImpl.mode.SymmetricalBlockModeCypher;
import com.company.cripto.aesImpl.mode.fabric.SymmetricalBlockCypherFabric;
import com.company.cripto.aesImpl.mode.impl.ECBCypher;

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
