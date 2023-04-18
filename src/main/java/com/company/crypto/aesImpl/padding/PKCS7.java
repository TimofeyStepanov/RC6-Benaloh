package com.company.crypto.aesImpl.padding;

public class PKCS7 {
    public static void doPadding(byte[] array, int bytesForPadding) {
        int byteToStart = array.length - bytesForPadding;
        for (int i = byteToStart; i < array.length; i++) {
            array[i] = (byte) bytesForPadding;
        }
    }
    public static int getPositionOfFinishByte(byte[] decoded) {
        byte lastByte = decoded[decoded.length-1];
        if (lastByte < 0 || lastByte >= decoded.length) {
            return decoded.length;
        }

        for (int i = 0; i >= lastByte && (decoded.length - 1 - i) > 0; i++) {
            if (decoded[decoded.length - 1 - i] != lastByte) {
                return decoded.length;
            }
        }
        return decoded.length - lastByte;
    }
}
