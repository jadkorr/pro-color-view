package com.procolorview.parser;

import com.procolorview.parser.ParsedHttpMessage.BodyType;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Parser de mensajes HTTP con detección automática de tipo de body
 * y pretty-printing para JSON, XML y form-urlencoded.
 */
public final class HttpMessageParser {

    private HttpMessageParser() {}

    private static final Pattern REQUEST_LINE =
            Pattern.compile("^[A-Z]{3,10}\\s+\\S+\\s+HTTP/\\d(?:\\.\\d)?$");

    private static final Pattern RESPONSE_LINE =
            Pattern.compile("^HTTP/\\d(?:\\.\\d)?\\s+\\d{3}.*$");

    /**
     * Parsea un mensaje HTTP crudo.
     */
    public static ParsedHttpMessage parse(String raw, boolean isRequest) {
        if (raw == null || raw.isEmpty()) {
            return new ParsedHttpMessage("", "", "", List.of(), BodyType.NONE, "", isRequest);
        }

        String[] parts = splitHeadBody(raw);
        String head = parts[0];
        String body = parts[1];

        String[] headLines = head.split("\\r?\\n");
        String startLine = headLines.length > 0 ? headLines[0] : "";

        List<Map.Entry<String, String>> headers = new ArrayList<>();
        for (int i = 1; i < headLines.length; i++) {
            String line = headLines[i];
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String name = line.substring(0, colonIdx);
                String value = line.substring(colonIdx + 1).stripLeading();
                headers.add(new AbstractMap.SimpleEntry<>(name, value));
            } else if (!line.isBlank()) {
                headers.add(new AbstractMap.SimpleEntry<>(line, ""));
            }
        }

        BodyType bodyType = detectBodyType(headers, body);
        String prettyBody = prettify(body, bodyType);

        return new ParsedHttpMessage(head, body, startLine, headers, bodyType, prettyBody, isRequest);
    }

    /**
     * Determina si una línea es una request line (e.g. "GET /path HTTP/1.1").
     */
    public static boolean isRequestLine(String line) {
        return REQUEST_LINE.matcher(line).matches();
    }

    /**
     * Determina si una línea es una response line (e.g. "HTTP/1.1 200 OK").
     */
    public static boolean isResponseLine(String line) {
        return RESPONSE_LINE.matcher(line).matches();
    }

    // ── Internos ────────────────────────────────────────────────────

    private static String[] splitHeadBody(String raw) {
        int idx = raw.indexOf("\r\n\r\n");
        if (idx >= 0) {
            return new String[]{ raw.substring(0, idx), raw.substring(idx + 4) };
        }
        idx = raw.indexOf("\n\n");
        if (idx >= 0) {
            return new String[]{ raw.substring(0, idx), raw.substring(idx + 2) };
        }
        return new String[]{ raw, "" };
    }

    private static BodyType detectBodyType(List<Map.Entry<String, String>> headers, String body) {
        // Primero chequear Content-Type
        for (var h : headers) {
            if (h.getKey().equalsIgnoreCase("content-type")) {
                String ct = h.getValue().toLowerCase();
                if (ct.contains("json")) return BodyType.JSON;
                if (ct.contains("xml")) return BodyType.XML;
                if (ct.contains("html")) return BodyType.HTML;
                if (ct.contains("javascript") || ct.contains("ecmascript")) return BodyType.JAVASCRIPT;
                if (ct.contains("x-www-form-urlencoded")) return BodyType.FORM;
            }
        }

        // Heurística basada en contenido
        String trimmed = body.stripLeading();
        if (trimmed.isEmpty()) return BodyType.NONE;

        if (trimmed.startsWith("{") || trimmed.startsWith("[")) return BodyType.JSON;
        if (trimmed.startsWith("<")) {
            String peek = trimmed.substring(0, Math.min(200, trimmed.length())).toLowerCase();
            if (peek.contains("<html") || peek.contains("<!doctype html")) return BodyType.HTML;
            return BodyType.XML;
        }
        if (trimmed.matches("^[A-Za-z0-9_.%+-]+=.*")) return BodyType.FORM;

        return BodyType.NONE;
    }

    private static String prettify(String body, BodyType type) {
        if (body == null || body.isBlank()) return "";

        return switch (type) {
            case JSON -> prettifyJson(body);
            // FORM: keep raw url-encoded format (key=val&key2=val2) — no prettification
            default -> body;
        };
    }

    /**
     * Pretty-print JSON con indentación.
     * Implementación manual ligera para evitar dependencias extra.
     */
    private static String prettifyJson(String json) {
        try {
            StringBuilder sb = new StringBuilder();
            int indent = 0;
            boolean inString = false;
            boolean escaped = false;

            for (int i = 0; i < json.length(); i++) {
                char c = json.charAt(i);

                if (escaped) {
                    sb.append(c);
                    escaped = false;
                    continue;
                }

                if (c == '\\' && inString) {
                    sb.append(c);
                    escaped = true;
                    continue;
                }

                if (c == '"') {
                    sb.append(c);
                    inString = !inString;
                    continue;
                }

                if (inString) {
                    sb.append(c);
                    continue;
                }

                // Ignorar whitespace fuera de strings
                if (Character.isWhitespace(c)) continue;

                switch (c) {
                    case '{', '[' -> {
                        sb.append(c);
                        indent++;
                        sb.append('\n').append("  ".repeat(indent));
                    }
                    case '}', ']' -> {
                        indent = Math.max(0, indent - 1);
                        sb.append('\n').append("  ".repeat(indent)).append(c);
                    }
                    case ',' -> {
                        sb.append(c);
                        sb.append('\n').append("  ".repeat(indent));
                    }
                    case ':' -> sb.append(": ");
                    default -> sb.append(c);
                }
            }
            return sb.toString();
        } catch (Exception e) {
            return json; // fallback al original
        }
    }

    /**
     * Minifica JSON: elimina TODO whitespace fuera de strings.
     * Funciona incluso si el JSON ya viene formateado del servidor.
     */
    public static String minifyJson(String json) {
        if (json == null || json.isEmpty()) return json;
        try {
            StringBuilder sb = new StringBuilder();
            boolean inString = false;
            boolean escaped = false;
            for (int i = 0; i < json.length(); i++) {
                char c = json.charAt(i);
                if (escaped) { sb.append(c); escaped = false; continue; }
                if (c == '\\' && inString) { sb.append(c); escaped = true; continue; }
                if (c == '"') { sb.append(c); inString = !inString; continue; }
                if (inString) { sb.append(c); continue; }
                if (!Character.isWhitespace(c)) sb.append(c);
            }
            return sb.toString();
        } catch (Exception e) {
            return json;
        }
    }

    /**
     * Pretty-print de form-urlencoded: decodifica y separa key=value.
     */
    private static String prettifyForm(String body) {
        try {
            StringBuilder sb = new StringBuilder();
            String[] pairs = body.split("&");
            for (int i = 0; i < pairs.length; i++) {
                if (pairs[i].isBlank()) continue;
                int eq = pairs[i].indexOf('=');
                String key, value;
                if (eq > 0) {
                    key = URLDecoder.decode(pairs[i].substring(0, eq), StandardCharsets.UTF_8);
                    value = URLDecoder.decode(pairs[i].substring(eq + 1), StandardCharsets.UTF_8);
                } else {
                    key = URLDecoder.decode(pairs[i], StandardCharsets.UTF_8);
                    value = "";
                }
                if (!sb.isEmpty()) sb.append('\n');
                sb.append(key).append(" = ").append(value);
            }
            return sb.isEmpty() ? body : sb.toString();
        } catch (Exception e) {
            return body;
        }
    }
}
