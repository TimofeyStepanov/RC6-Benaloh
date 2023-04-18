package com.company.crypto.aesImpl.mode.fabric.impl;

import com.company.crypto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.crypto.aesImpl.mode.SymmetricalBlockModeCypher;
import com.company.crypto.aesImpl.mode.fabric.SymmetricalBlockCypherFabric;
import com.company.crypto.aesImpl.mode.impl.CTRCypher;

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
