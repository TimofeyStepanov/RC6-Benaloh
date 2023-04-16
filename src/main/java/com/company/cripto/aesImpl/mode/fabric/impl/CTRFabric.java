package com.company.cripto.aesImpl.mode.fabric.impl;

import com.company.cripto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.cripto.aesImpl.mode.SymmetricalBlockModeCypher;
import com.company.cripto.aesImpl.mode.fabric.SymmetricalBlockCypherFabric;
import com.company.cripto.aesImpl.mode.impl.CTRCypher;

import java.util.Objects;

public class CTRFabric extends SymmetricalBlockCypherFabric {
    @Override
    public SymmetricalBlockModeCypher create(SymmetricalBlockEncryptionAlgorithm algorithm, Object... args) {
        Objects.requireNonNull(args);

        int positionOfStartIndex = ArgPosition.INDEX_FOR_CTR.position;
        if (args.length <= positionOfStartIndex) {
            throw new IllegalArgumentException("Wrong args length. No start index");
        }

        return new CTRCypher(algorithm, (int) args[positionOfStartIndex]);
    }
}
