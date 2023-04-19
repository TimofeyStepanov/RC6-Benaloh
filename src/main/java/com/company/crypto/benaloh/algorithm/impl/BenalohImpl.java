package com.company.crypto.benaloh.algorithm.impl;

import com.company.crypto.benaloh.algebra.prime.PrimeChecker;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerFabric;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerType;
import com.company.crypto.benaloh.algorithm.Benaloh;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

@Slf4j
public final class BenalohImpl extends Benaloh {
    private static final int MIN_LENGTH_OF_PRIME_DIGIT = 64;

    private OpenKey openKey;
    private PrivateKey privateKey;
    private final OpenKeyGenerator openKeyGenerator;
    private final Random random = new Random();

    public BenalohImpl(PrimeCheckerType type, double precision, int rLength) {
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
        log.info("message to encode:" + message);

        BigInteger r = openKey.getR();
        if (message.compareTo(r) >= 0) {
            throw new IllegalArgumentException("Wrong message to encode");
        }

        BigInteger n = openKey.getN();
        BigInteger u = getRandomPositiveDigit(n);

        BigInteger y = openKey.getY();
        BigInteger yInDegree = y.modPow(message, n);
        BigInteger uInDegree = u.modPow(r, n);
        BigInteger encodedMessage = yInDegree.multiply(uInDegree).mod(n);
        log.info("message encoded:" + encodedMessage);

        byte[] arrayOfEncodedMessage = encodedMessage.toByteArray();
        reverseArray(arrayOfEncodedMessage);
        arrayOfEncodedMessage = deleteLastElementOfArrayIfItZero(arrayOfEncodedMessage);
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

    private BigInteger getRandomPositiveDigit(BigInteger maxDigit) {
        BigInteger randomDigit;
        do {
            int randomLength = Math.abs(ThreadLocalRandom.current().nextInt() % maxDigit.bitLength());
            randomDigit = new BigInteger(randomLength, random);
        } while (!(randomDigit.compareTo(BigInteger.ZERO) > 0 && randomDigit.compareTo(maxDigit) < 0));
        return randomDigit;
    }

    private byte[] deleteLastElementOfArrayIfItZero(byte[] decodedMessageBytes) {
        if (decodedMessageBytes.length > 1 && decodedMessageBytes[decodedMessageBytes.length - 1] == 0) {
            return Arrays.copyOfRange(decodedMessageBytes, 0, decodedMessageBytes.length - 1);
        }
        return decodedMessageBytes;
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
        log.info("message to decode:" + message);
        if (message.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Wrong message to decode");
        }

        BigInteger a = message.modPow(f.divide(r), n);
        BigInteger decodedMessage = getDiscreteLogarithm(privateKey.getX(), a, n);
        log.info("decoded message:" + decodedMessage);

        byte[] arrayOfDecodedMessage = decodedMessage.toByteArray();
        reverseArray(arrayOfDecodedMessage);
        arrayOfDecodedMessage = deleteLastElementOfArrayIfItZero(arrayOfDecodedMessage);
        return arrayOfDecodedMessage;
    }

    private BigInteger getDiscreteLogarithm(BigInteger base, BigInteger arg, BigInteger modulo) {
//        BigInteger m = BigInteger.ZERO;
//        BigInteger r = openKey.getR();
//        while (!m.equals(r)) {
//            BigInteger toCheck = base.modPow(m, modulo);
//            if (toCheck.equals(arg)) {
//                log.info("i:" + m);
//                return m;
//            }
//            m = m.add(BigInteger.ONE);
//        }


        BigInteger maxIterationNumber = modulo.sqrt().add(BigInteger.ONE);
        BigInteger aInDegreeN = BigInteger.ONE;
        BigInteger i = BigInteger.ZERO;
        while (!i.equals(maxIterationNumber)) {
            aInDegreeN = aInDegreeN.multiply(base).mod(modulo);
            i = i.add(BigInteger.ONE);
        }

        Map<BigInteger, BigInteger> values = new HashMap<>();
        i = BigInteger.ONE;
        BigInteger current = aInDegreeN;
        while (i.compareTo(maxIterationNumber) <= 0) {
            values.putIfAbsent(current, i);
            current = current.multiply(aInDegreeN).mod(modulo);
            i = i.add(BigInteger.ONE);
        }

        i = BigInteger.ZERO;
        current = arg;
        while (i.compareTo(maxIterationNumber) <= 0) {
            if (values.containsKey(current)) {
                BigInteger value = values.get(current);
                BigInteger answer = value.multiply(maxIterationNumber).subtract(i);
                if (answer.compareTo(modulo) < 0) {
                    return answer;
                }
            }
            current = current.multiply(base).mod(modulo);
            i = i.add(BigInteger.ONE);
        }
        throw new IllegalArgumentException("Can't find discrete l");
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

            int randomLength = MIN_LENGTH_OF_PRIME_DIGIT + ThreadLocalRandom.current().nextInt(0, MIN_LENGTH_OF_PRIME_DIGIT);
            do {
                p = generateRandomPrimeDigit(randomLength);
                pMinusOne = p.subtract(BigInteger.ONE);
            } while (!pMinusOne.mod(r).equals(BigInteger.ZERO) || !getGCD(r, pMinusOne.divide(r)).equals(BigInteger.ONE));

            BigInteger q;
            BigInteger qMinusOne;
            BigInteger gcd;
            do {
                q = generateRandomPrimeDigit(r);
                qMinusOne = q.subtract(BigInteger.ONE);
                gcd = getGCD(qMinusOne, r);
            } while (!gcd.equals(BigInteger.ONE) || p.equals(q));

            BigInteger n = p.multiply(q);
            BigInteger f = p.subtract(BigInteger.ONE).multiply(qMinusOne);
            BigInteger yDegree = f.divide(r);
            BigInteger y;
            BigInteger x;
            do {
                y = getRandomPositiveDigit(n);
                x = y.modPow(yDegree, n);
                gcd = getGCD(x, n);
            } while (gcd.equals(BigInteger.ONE) || y.equals(n));

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
