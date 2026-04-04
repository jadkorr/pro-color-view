package com.procolorview.util;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utilidades de encode/decode para el panel de decodificación en vivo.
 *
 * Cada método retorna null si el input no es decodificable en ese formato,
 * o el resultado decodificado si lo es.
 *
 * Soporta: Base64, URL, Hex, HTML entities, JWT, Unicode escapes.
 */
public final class Decoder {

    private Decoder() {}

    private static final Pattern B64_STRICT =
            Pattern.compile("^[A-Za-z0-9+/]{4,}={0,2}$");
    private static final Pattern B64URL_STRICT =
            Pattern.compile("^[A-Za-z0-9_-]{4,}={0,2}$");
    private static final Pattern HEX_PATTERN =
            Pattern.compile("^([0-9a-fA-F]{2})+$");
    private static final Pattern URL_ENCODED =
            Pattern.compile("%[0-9a-fA-F]{2}");
    private static final Pattern HTML_ENTITY =
            Pattern.compile("&(#?\\w+);");
    private static final Pattern UNICODE_ESC =
            Pattern.compile("\\\\u[0-9a-fA-F]{4}");
    private static final Pattern JWT_PATTERN =
            Pattern.compile("^eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$");

    /**
     * Intenta todos los decodings aplicables y retorna los resultados.
     * Key = nombre del formato, Value = resultado decodificado.
     * Solo incluye decodings exitosos y que producen texto legible.
     */
    public static Map<String, String> decodeAll(String input) {
        Map<String, String> results = new LinkedHashMap<>();
        if (input == null || input.isEmpty()) return results;

        String trimmed = input.strip();

        // JWT (prioridad alta si matchea)
        String jwt = jwtDecode(trimmed);
        if (jwt != null) results.put("JWT", jwt);

        // Base64
        String b64 = base64Decode(trimmed);
        if (b64 != null) results.put("Base64", b64);

        // URL decode
        String url = urlDecode(trimmed);
        if (url != null && !url.equals(trimmed)) results.put("URL", url);

        // Hex
        String hex = hexDecode(trimmed);
        if (hex != null) results.put("Hex", hex);

        // HTML entities
        String html = htmlDecode(trimmed);
        if (html != null && !html.equals(trimmed)) results.put("HTML", html);

        // Unicode escapes
        String uni = unicodeUnescape(trimmed);
        if (uni != null && !uni.equals(trimmed)) results.put("Unicode", uni);

        return results;
    }

    /**
     * Genera los encodings comunes del texto seleccionado.
     */
    public static Map<String, String> encodeAll(String input) {
        Map<String, String> results = new LinkedHashMap<>();
        if (input == null || input.isEmpty()) return results;

        results.put("Base64", base64Encode(input));
        results.put("URL", urlEncode(input));
        results.put("Hex", hexEncode(input));
        results.put("HTML", htmlEncode(input));

        return results;
    }

    // ── Decode ──────────────────────────────────────────────────────

    public static String base64Decode(String input) {
        if (input == null || input.length() < 4) return null;

        // Intentar base64 estándar
        if (B64_STRICT.matcher(input).matches()) {
            try {
                byte[] decoded = Base64.getDecoder().decode(input);
                String result = new String(decoded, StandardCharsets.UTF_8);
                return isPrintable(result) ? result : null;
            } catch (Exception ignored) {}
        }

        // Intentar base64url
        if (B64URL_STRICT.matcher(input).matches()) {
            try {
                byte[] decoded = Base64.getUrlDecoder().decode(input);
                String result = new String(decoded, StandardCharsets.UTF_8);
                return isPrintable(result) ? result : null;
            } catch (Exception ignored) {}
        }

        return null;
    }

    public static String base64Encode(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String urlDecode(String input) {
        if (input == null || !URL_ENCODED.matcher(input).find()) return null;
        try {
            return URLDecoder.decode(input, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public static String urlEncode(String input) {
        return URLEncoder.encode(input, StandardCharsets.UTF_8);
    }

    public static String hexDecode(String input) {
        if (input == null) return null;
        String clean = input.replaceAll("[\\s:.-]", "");
        if (clean.length() < 4 || !HEX_PATTERN.matcher(clean).matches()) return null;
        try {
            byte[] bytes = new byte[clean.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
            }
            String result = new String(bytes, StandardCharsets.UTF_8);
            return isPrintable(result) ? result : null;
        } catch (Exception e) {
            return null;
        }
    }

    public static String hexEncode(String input) {
        StringBuilder sb = new StringBuilder();
        for (byte b : input.getBytes(StandardCharsets.UTF_8)) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String htmlDecode(String input) {
        if (input == null || !HTML_ENTITY.matcher(input).find()) return null;
        try {
            String result = input;
            result = result.replace("&amp;", "&");
            result = result.replace("&lt;", "<");
            result = result.replace("&gt;", ">");
            result = result.replace("&quot;", "\"");
            result = result.replace("&apos;", "'");
            result = result.replace("&#39;", "'");
            result = result.replace("&nbsp;", " ");
            // Numeric entities: &#123; → char
            Matcher numMatcher = Pattern.compile("&#(\\d+);").matcher(result);
            StringBuilder numSb = new StringBuilder();
            while (numMatcher.find()) {
                try {
                    int code = Integer.parseInt(numMatcher.group(1));
                    numMatcher.appendReplacement(numSb, String.valueOf((char) code));
                } catch (Exception e) { numMatcher.appendReplacement(numSb, numMatcher.group()); }
            }
            numMatcher.appendTail(numSb);
            result = numSb.toString();

            // Hex entities: &#xAB; → char
            Matcher hexMatcher = Pattern.compile("&#x([0-9a-fA-F]+);").matcher(result);
            StringBuilder hexSb = new StringBuilder();
            while (hexMatcher.find()) {
                try {
                    int code = Integer.parseInt(hexMatcher.group(1), 16);
                    hexMatcher.appendReplacement(hexSb, String.valueOf((char) code));
                } catch (Exception e) { hexMatcher.appendReplacement(hexSb, hexMatcher.group()); }
            }
            hexMatcher.appendTail(hexSb);
            result = hexSb.toString();
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    public static String htmlEncode(String input) {
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    public static String unicodeUnescape(String input) {
        if (input == null || !UNICODE_ESC.matcher(input).find()) return null;
        try {
            StringBuilder sb = new StringBuilder();
            int i = 0;
            while (i < input.length()) {
                if (i + 5 < input.length() && input.charAt(i) == '\\' && input.charAt(i + 1) == 'u') {
                    String hex = input.substring(i + 2, i + 6);
                    sb.append((char) Integer.parseInt(hex, 16));
                    i += 6;
                } else {
                    sb.append(input.charAt(i));
                    i++;
                }
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static String jwtDecode(String input) {
        if (input == null || !JWT_PATTERN.matcher(input.strip()).matches()) return null;

        String[] parts = input.strip().split("\\.");
        if (parts.length < 2) return null;

        StringBuilder sb = new StringBuilder();
        sb.append("Header: ").append(decodeJwtPart(parts[0]));
        sb.append(" | Payload: ").append(decodeJwtPart(parts[1]));
        return sb.toString();
    }

    /**
     * Decodifica un JWT completo con formato multi-línea (para diálogo).
     */
    public static String jwtDecodeFull(String input) {
        if (input == null) return null;
        String trimmed = input.strip();
        if (!JWT_PATTERN.matcher(trimmed).matches()) return null;

        String[] parts = trimmed.split("\\.");
        if (parts.length < 2) return null;

        StringBuilder sb = new StringBuilder();
        sb.append("HEADER:\n").append(decodeJwtPart(parts[0])).append("\n\n");
        sb.append("PAYLOAD:\n").append(decodeJwtPart(parts[1])).append("\n");
        if (parts.length > 2) {
            sb.append("\nSIGNATURE: ").append(parts[2], 0, Math.min(40, parts[2].length()));
            if (parts[2].length() > 40) sb.append("...");
        }
        return sb.toString();
    }

    private static String decodeJwtPart(String part) {
        try {
            String padded = part.replace('-', '+').replace('_', '/');
            while (padded.length() % 4 != 0) padded += "=";
            byte[] decoded = Base64.getDecoder().decode(padded);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "(error)";
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────

    private static boolean isPrintable(String s) {
        if (s == null || s.isEmpty()) return false;
        int printable = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 32 && c < 127) || c == '\n' || c == '\r' || c == '\t') {
                printable++;
            }
        }
        return (double) printable / s.length() > 0.7;
    }
}
