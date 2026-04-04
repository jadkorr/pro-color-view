package com.procolorview.util;

import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detecta y decodifica strings Base64 en texto HTTP.
 * Útil para encontrar datos codificados en headers, cookies, body, etc.
 *
 * Solo muestra strings decodificados que parecen texto legible (>80% printable).
 */
public final class Base64Detector {

    private Base64Detector() {}

    // Base64 estándar: al menos 20 chars, terminado opcionalmente en =
    private static final Pattern B64_PATTERN =
            Pattern.compile("(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])");

    // Base64url: usa - y _ en lugar de + y /
    private static final Pattern B64URL_PATTERN =
            Pattern.compile("(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{20,}={0,2})(?![A-Za-z0-9_-=])");

    /**
     * Busca y decodifica strings Base64/Base64url en el texto.
     */
    public static String findAndDecode(String text) {
        if (text == null || text.isEmpty()) return "No Base64 strings found.";

        StringBuilder sb = new StringBuilder();
        int count = 0;

        // Buscar base64 estándar
        count = findMatches(text, B64_PATTERN, false, sb, count);

        // Buscar base64url (sin duplicar lo que ya encontramos)
        count = findMatches(text, B64URL_PATTERN, true, sb, count);

        if (sb.isEmpty()) return "No decodable Base64 strings found in content.";

        sb.insert(0, "Found " + count + " Base64 encoded string(s):\n\n");
        return sb.toString();
    }

    private static int findMatches(String text, Pattern pattern, boolean isUrl,
                                   StringBuilder sb, int startCount) {
        Matcher m = pattern.matcher(text);
        int count = startCount;

        while (m.find() && count < 20) {
            String encoded = m.group(1);
            try {
                byte[] decoded;
                if (isUrl) {
                    String std = encoded.replace('-', '+').replace('_', '/');
                    while (std.length() % 4 != 0) std += "=";
                    decoded = Base64.getDecoder().decode(std);
                } else {
                    decoded = Base64.getDecoder().decode(encoded);
                }

                String decodedStr = new String(decoded);

                // Solo mostrar si parece texto legible
                if (isPrintable(decodedStr) && decodedStr.length() >= 3) {
                    count++;
                    sb.append("━━━ Base64 #").append(count);
                    if (isUrl) sb.append(" (URL-safe)");
                    sb.append(" ━━━\n");

                    // Mostrar encoded truncado
                    sb.append("Encoded: ");
                    if (encoded.length() > 60) {
                        sb.append(encoded, 0, 60).append("...");
                    } else {
                        sb.append(encoded);
                    }
                    sb.append("\n");

                    // Mostrar decoded
                    sb.append("Decoded: ");
                    if (decodedStr.length() > 500) {
                        sb.append(decodedStr, 0, 500).append("...");
                    } else {
                        sb.append(decodedStr);
                    }
                    sb.append("\n\n");
                }
            } catch (Exception ignored) {}
        }

        return count;
    }

    /**
     * Verifica si un string es mayoritariamente printable (ASCII 32-126).
     */
    private static boolean isPrintable(String s) {
        if (s == null || s.isEmpty()) return false;
        int printable = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 32 && c < 127) || c == '\n' || c == '\r' || c == '\t') {
                printable++;
            }
        }
        return (double) printable / s.length() > 0.8;
    }
}
