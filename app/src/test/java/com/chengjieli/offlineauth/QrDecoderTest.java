package com.chengjieli.offlineauth;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.junit.Test;

import static org.junit.Assert.*;

/** All secrets in this suite are public RFC test data, never real user account credentials. */
public final class QrDecoderTest {
    private static final String URI = "otpauth://totp/Example%3Atest%40example.com"
            + "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";

    @Test public void decodesStandardArgbQr() throws Exception {
        BitMatrix matrix = qr(URI);
        assertEquals(URI, QrDecoder.decodeArgb(argb(matrix, false), matrix.getWidth(), matrix.getHeight()));
    }

    @Test public void decodesInvertedQr() throws Exception {
        BitMatrix matrix = qr(URI);
        assertEquals(URI, QrDecoder.decodeArgb(argb(matrix, true), matrix.getWidth(), matrix.getHeight()));
    }

    @Test public void decodesQrInAllFourRotations() throws Exception {
        BitMatrix matrix = qr(URI);
        for (int quarterTurn = 0; quarterTurn < 4; quarterTurn++) {
            assertEquals("QR rotation " + (quarterTurn * 90), URI,
                    QrDecoder.decodeArgb(argb(matrix, false), matrix.getWidth(), matrix.getHeight()));
            matrix.rotate90();
        }
    }

    @Test public void decodesCameraLuminance() throws Exception {
        BitMatrix matrix = qr(URI);
        byte[] y = new byte[matrix.getWidth() * matrix.getHeight()];
        for (int row = 0; row < matrix.getHeight(); row++) {
            for (int column = 0; column < matrix.getWidth(); column++) {
                y[row * matrix.getWidth() + column] = (byte) (matrix.get(column, row) ? 0 : 255);
            }
        }
        assertEquals(URI, QrDecoder.decodeLuminance(y, matrix.getWidth(), matrix.getHeight()));
    }

    @Test public void returnsNullForNoQr() {
        int[] blank = new int[300 * 300];
        java.util.Arrays.fill(blank, 0xFFFFFFFF);
        assertNull(QrDecoder.decodeArgb(blank, 300, 300));
    }

    @Test public void acceptsOnlyTotpRoutingUris() {
        assertTrue(QrDecoder.isSupportedTotpUri(URI));
        assertTrue(QrDecoder.isSupportedTotpUri("OTPAUTH://TOTP/test?secret=EXAMPLE"));
        assertFalse(QrDecoder.isSupportedTotpUri(null));
        assertFalse(QrDecoder.isSupportedTotpUri("https://example.com"));
        assertFalse(QrDecoder.isSupportedTotpUri("otpauth://hotp/test?secret=EXAMPLE"));
        assertFalse(QrDecoder.isSupportedTotpUri("otpauth://totp.evil/test?secret=EXAMPLE"));
        assertFalse(QrDecoder.isSupportedTotpUri("otpauth://user@totp/test?secret=EXAMPLE"));
        assertFalse(QrDecoder.isSupportedTotpUri("otpauth://totp:80/test?secret=EXAMPLE"));
        assertFalse(QrDecoder.isSupportedTotpUri("otpauth://totp/"));
        assertFalse(QrDecoder.isSupportedTotpUri("otpauth://totp/test?secret=EXAMPLE#fragment"));
        assertFalse(QrDecoder.isSupportedTotpUri("otpauth://totp/" + "x".repeat(8192)));
    }

    private BitMatrix qr(String text) throws WriterException {
        return new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 600, 600);
    }

    private int[] argb(BitMatrix matrix, boolean inverted) {
        int[] pixels = new int[matrix.getWidth() * matrix.getHeight()];
        for (int row = 0; row < matrix.getHeight(); row++) {
            for (int column = 0; column < matrix.getWidth(); column++) {
                pixels[row * matrix.getWidth() + column] = matrix.get(column, row) != inverted
                        ? 0xFF000000 : 0xFFFFFFFF;
            }
        }
        return pixels;
    }
}
