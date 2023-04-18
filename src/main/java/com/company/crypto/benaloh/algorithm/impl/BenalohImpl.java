package com.company.crypto.benaloh.algorithm.impl;

import com.company.crypto.benaloh.algebra.prime.PrimeChecker;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerFabric;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerType;
import com.company.crypto.benaloh.algorithm.Benaloh;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public final class BenalohImpl extends Benaloh {
    private static final int MIN_LENGTH_OF_PRIME_DIGIT = 64;

    private OpenKey openKey;
    private PrivateKey privateKey;
    private final OpenKeyGenerator openKeyGenerator;
    private final Random random = new Random();

    private BenalohImpl(PrimeCheckerType type, double precision, int rLength) {
        this.openKeyGenerator = new OpenKeyGenerator(type, precision, rLength);
        this.openKeyGenerator.generateOpenAndPrivateKey();
    }

    @Override
    public byte[] encode(byte[] array, OpenKey openKey) {
        Objects.requireNonNull(array);
        if (array.length == 0) {
            return new byte[0];
        }

        BigInteger message = translateInputByteArrayToBigInteger(array);
        BigInteger u = getRandomPositiveDigit();

        BigInteger y = openKey.getY();
        BigInteger yInDegree = y.modPow(message, openKey.getN());
        BigInteger uInDegree = u.modPow(openKey.getR(), openKey.getN());
        BigInteger encodedMessage = yInDegree.multiply(uInDegree).mod(openKey.getN());

        byte[] arrayOfEncodedMessage = encodedMessage.toByteArray();
        reverseArray(arrayOfEncodedMessage);
        return arrayOfEncodedMessage;
    }

    private BigInteger translateInputByteArrayToBigInteger(byte[] array) {
        byte[] copiedArray = Arrays.copyOf(array, array.length);
        reverseArray(copiedArray);
        return new BigInteger(1, copiedArray);
    }

    private void reverseArray(byte[] array) {
        for (int i = 0; i < array.length / 2; i++) {
            byte tmp = array[i];
            array[i] = array[array.length - 1 - i];
            array[array.length - 1 - i] = tmp;
        }
    }

    private BigInteger getRandomPositiveDigit() {
        BigInteger randomDigit;
        do {
            randomDigit = new BigInteger(MIN_LENGTH_OF_PRIME_DIGIT, random);
        } while (randomDigit.compareTo(BigInteger.ZERO) <= 0);
        return randomDigit;
    }

    @Override
    public byte[] decode(byte[] array) {
        Objects.requireNonNull(array);
        if (array.length == 0) {
            return new byte[0];
        }

        BigInteger f = privateKey.getF();
        BigInteger n = openKey.getN();
        BigInteger r = openKey.getR();

        BigInteger message = translateInputByteArrayToBigInteger(array);
        BigInteger a  = message.modPow(f.divide(r), n);
        BigInteger decodedMessage = getDiscreteLogarithm(privateKey.getX(), a, r, n);

        byte[] arrayOfDecodedMessage = decodedMessage.toByteArray();
        reverseArray(arrayOfDecodedMessage);
        return arrayOfDecodedMessage;
    }

    private BigInteger getDiscreteLogarithm(BigInteger x, BigInteger a, BigInteger r, BigInteger n) {
        BigInteger i = BigInteger.ZERO;
        while (!i.equals(r)) {
            BigInteger toCheck = x.modPow(i, n);
            if (toCheck.equals(a)) {
                return i;
            }
            i = i.add(BigInteger.ONE);
        }
        throw new UnsupportedOperationException("Can't find discrete l");
    }

    @Override
    public void regenerateOpenKey() {
        this.openKeyGenerator.generateOpenAndPrivateKey();
    }

    @Override
    public OpenKey getOpenKey() {
        return openKey;
    }

    class OpenKeyGenerator {
        private final PrimeChecker primeChecker;
        private final double precision;
        private final int rLength;

        public OpenKeyGenerator(PrimeCheckerType type, double precision, int rLength) {
            this.primeChecker = PrimeCheckerFabric.getInstance(type);
            this.precision = precision;
            this.rLength = rLength;
        }

        public void generateOpenAndPrivateKey() {
            BigInteger r = generateRandomPrimeDigit(rLength);
            BigInteger p;
            BigInteger pMinusOne;
            do {
                p = generateRandomPrimeDigit(r);
                pMinusOne = p.subtract(BigInteger.ONE);
            } while (!pMinusOne.mod(r).equals(BigInteger.ZERO));

            BigInteger q;
            BigInteger qMinusOne;
            BigInteger gcd;
            do {
                q = generateRandomPrimeDigit(MIN_LENGTH_OF_PRIME_DIGIT
                        + ThreadLocalRandom.current().nextInt(0, MIN_LENGTH_OF_PRIME_DIGIT));
                qMinusOne = q.subtract(BigInteger.ONE);
                gcd = getGCD(qMinusOne, r);
            } while (!gcd.equals(BigInteger.ONE) || p.equals(q));

            BigInteger n = p.multiply(q);
            BigInteger f = p.subtract(BigInteger.ONE).multiply(qMinusOne);
            BigInteger yDegree = f.divide(r);
            BigInteger y;
            BigInteger x;
            do {
                y = generateRandomPrimeDigit(MIN_LENGTH_OF_PRIME_DIGIT
                        + ThreadLocalRandom.current().nextInt(0, MIN_LENGTH_OF_PRIME_DIGIT));
                x = y.modPow(yDegree, n);
                gcd = getGCD(x, n);
            } while (!gcd.equals(BigInteger.ONE) || y.equals(n));

            BenalohImpl.this.openKey = new OpenKey(y, r, n);
            BenalohImpl.this.privateKey = new PrivateKey(f, x);
        }

        private BigInteger generateRandomPrimeDigit(int digitLength) {
            BitSet bitSet = new BitSet(digitLength);
            bitSet.set(0, true);
            bitSet.set(digitLength - 1, true);

            BigInteger randomEvenDigit;
            do {
                for (int i = 1; i < digitLength - 1; i++) {
                    bitSet.set(i, ThreadLocalRandom.current().nextBoolean());
                }

                byte[] bitSetByteArray = bitSet.toByteArray();
                reverseArray(bitSetByteArray);
                randomEvenDigit = new BigInteger(1, bitSetByteArray);
            } while (!primeChecker.isPrime(randomEvenDigit, precision));
            return randomEvenDigit;
        }

        private BigInteger generateRandomPrimeDigit(BigInteger minDigit) {
            int digitLength = minDigit.bitLength() + ThreadLocalRandom.current().nextInt(1, minDigit.bitLength());
            return generateRandomPrimeDigit(digitLength);
        }

        private BigInteger getGCD(BigInteger firstDigit, BigInteger secondDigit) {
            if (secondDigit.equals(BigInteger.ZERO)) {
                return firstDigit;
            }
            return getGCD(secondDigit, firstDigit.mod(secondDigit));
        }
    }
}
