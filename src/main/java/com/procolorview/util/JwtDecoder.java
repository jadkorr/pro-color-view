package com.procolorview.util;

import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detecta y decodifica tokens JWT en texto HTTP.
 * JWT format: header.payload.signature (cada parte en base64url).
 *
 * Detecta tokens en headers como Authorization: Bearer eyJ...
 * y en cualquier parte del body.
 */
public final class JwtDecoder {

    private JwtDecoder() {}

    // Patrón JWT: eyJ + base64url . eyJ + base64url . base64url
    private static final Pattern JWT_PATTERN =
            Pattern.compile("(eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*)");

    /**
     * Busca y decodifica todos los JWT encontrados en el texto.
     */
    public static String findAndDecode(String text) {
        if (text == null || text.isEmpty()) return "No JWT tokens found.";

        Matcher m = JWT_PATTERN.matcher(text);
        StringBuilder sb = new StringBuilder();
        int count = 0;

        while (m.find() && count < 10) {
            count++;
            String jwt = m.group(1);
            String[] parts = jwt.split("\\.");

            sb.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            sb.append("  JWT Token #").append(count).append("\n");
            sb.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

            if (parts.length >= 1) {
                sb.append("HEADER:\n");
                sb.append(decodeBase64Url(parts[0])).append("\n\n");
            }

            if (parts.length >= 2) {
                sb.append("PAYLOAD:\n");
                sb.append(decodeBase64Url(parts[1])).append("\n\n");
            }

            if (parts.length >= 3) {
                String sig = parts[2];
                sb.append("SIGNATURE: ");
                sb.append(sig, 0, Math.min(40, sig.length()));
                if (sig.length() > 40) sb.append("...");
                sb.append("\n\n");
            }

            // Mostrar el token original (truncado)
            sb.append("RAW (truncated): ");
            sb.append(jwt, 0, Math.min(80, jwt.length()));
            if (jwt.length() > 80) sb.append("...");
            sb.append("\n\n");
        }

        if (sb.isEmpty()) return "No JWT tokens found in content.";

        sb.insert(0, "Found " + count + " JWT token(s):\n\n");
        return sb.toString();
    }

    /**
     * Verifica si el texto contiene al menos un JWT.
     */
    public static boolean containsJwt(String text) {
        if (text == null) return false;
        return JWT_PATTERN.matcher(text).find();
    }

    /**
     * Decodifica una parte base64url de un JWT a texto legible.
     */
    private static String decodeBase64Url(String encoded) {
        try {
            String base64 = encoded.replace('-', '+').replace('_', '/');
            while (base64.length() % 4 != 0) base64 += "=";
            byte[] decoded = Base64.getDecoder().decode(base64);
            return prettyJson(new String(decoded));
        } catch (Exception e) {
            return "(decode error: " + e.getMessage() + ")";
        }
    }

    /**
     * Pretty-print simple de JSON para la salida del decoder.
     */
    private static String prettyJson(String json) {
        try {
            StringBuilder sb = new StringBuilder();
            int indent = 0;
            boolean inString = false;
            boolean escaped = false;

            for (int i = 0; i < json.length(); i++) {
                char c = json.charAt(i);

                if (escaped) { sb.append(c); escaped = false; continue; }
                if (c == '\\' && inString) { sb.append(c); escaped = true; continue; }
                if (c == '"') { sb.append(c); inString = !inString; continue; }
                if (inString) { sb.append(c); continue; }
                if (Character.isWhitespace(c)) continue;

                switch (c) {
                    case '{', '[' -> {
                        sb.append(c).append('\n');
                        indent++;
                        sb.append("  ".repeat(indent));
                    }
                    case '}', ']' -> {
                        indent = Math.max(0, indent - 1);
                        sb.append('\n').append("  ".repeat(indent)).append(c);
                    }
                    case ',' -> sb.append(c).append('\n').append("  ".repeat(indent));
                    case ':' -> sb.append(": ");
                    default -> sb.append(c);
                }
            }
            return sb.toString();
        } catch (Exception e) {
            return json;
        }
    }
}
