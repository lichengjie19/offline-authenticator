package com.chengjieli.offlineauth;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.LuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

/** Offline QR decoding. Never logs or persists a scanned payload. */
public final class QrDecoder {
    private static final Map<DecodeHintType, Object> HINTS;

    static {
        HINTS = new EnumMap<>(DecodeHintType.class);
        HINTS.put(DecodeHintType.POSSIBLE_FORMATS, Collections.singletonList(BarcodeFormat.QR_CODE));
        HINTS.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
        HINTS.put(DecodeHintType.CHARACTER_SET, "UTF-8");
    }

    private QrDecoder() {}

    public static String decodeLuminance(byte[] pixels, int width, int height) {
        return decode(new PlanarYUVLuminanceSource(pixels, width, height, 0, 0,
                width, height, false));
    }

    public static String decodeArgb(int[] pixels, int width, int height) {
        return decode(new RGBLuminanceSource(width, height, pixels));
    }

    private static String decode(LuminanceSource source) {
        MultiFormatReader reader = new MultiFormatReader();
        try {
            return reader.decode(new BinaryBitmap(new HybridBinarizer(source)), HINTS).getText();
        } catch (NotFoundException absent) {
            // Inverted dark-theme QR codes are also common on account setup pages.
            try {
                reader.reset();
                return reader.decode(new BinaryBitmap(new HybridBinarizer(source.invert())), HINTS)
                        .getText();
            } catch (NotFoundException stillAbsent) {
                return null;
            }
        } finally {
            reader.reset();
        }
    }

    /** Only a routing check; the account parser validates all TOTP parameters afterwards. */
    public static boolean isSupportedTotpUri(String text) {
        if (text == null || text.length() > 8192) return false;
        try {
            URI uri = new URI(text);
            return "otpauth".equalsIgnoreCase(uri.getScheme())
                    && "totp".equalsIgnoreCase(uri.getRawAuthority())
                    && uri.getRawPath() != null
                    && uri.getRawPath().length() > 1
                    && uri.getRawFragment() == null;
        } catch (URISyntaxException invalid) {
            return false;
        }
    }
}
