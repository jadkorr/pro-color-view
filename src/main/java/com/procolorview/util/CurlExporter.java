package com.procolorview.util;

import com.procolorview.parser.ParsedHttpMessage;

import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Convierte un HTTP request a cURL MÍNIMO: solo lo necesario para que funcione.
 *
 * Incluye:
 *   - Método (si no es GET)
 *   - URL completa (scheme + host + path)
 *   - Solo headers ESENCIALES para que el request funcione:
 *     Cookie, Authorization, Content-Type, X-* custom headers, Origin, Referer
 *   - Body si existe
 *   - -k para ignorar SSL (pentesting)
 *
 * NO incluye: User-Agent, Accept, Accept-Language, Accept-Encoding,
 * Connection, Sec-*, Upgrade-*, Cache-Control, Pragma, etc.
 */
public final class CurlExporter {

    private CurlExporter() {}

    private static final Pattern REQUEST_LINE =
            Pattern.compile("^([A-Z]+)\\s+(\\S+)\\s+HTTP/");

    // Headers que se OMITEN (no son necesarios para que funcione el request)
    private static final Set<String> SKIP_HEADERS = Set.of(
            "host", "content-length", "connection", "accept",
            "accept-language", "accept-encoding", "user-agent",
            "cache-control", "pragma", "upgrade-insecure-requests",
            "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
            "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile",
            "sec-ch-ua-platform", "te", "dnt", "if-none-match",
            "if-modified-since"
    );

    public static String toCurl(ParsedHttpMessage msg) {
        if (!msg.isRequest()) return "# Solo requests";

        StringBuilder sb = new StringBuilder("curl -k");

        Matcher m = REQUEST_LINE.matcher(msg.startLine());
        String method = "GET";
        String path = "/";
        if (m.find()) {
            method = m.group(1);
            path = m.group(2);
        }

        // Host
        String host = "";
        for (var h : msg.headers()) {
            if (h.getKey().equalsIgnoreCase("host")) {
                host = h.getValue().strip();
                break;
            }
        }

        // Método solo si no es GET
        if (!"GET".equals(method)) {
            sb.append(" -X ").append(method);
        }

        // URL
        sb.append(" 'https://").append(esc(host)).append(esc(path)).append("'");

        // Solo headers esenciales
        for (var h : msg.headers()) {
            String name = h.getKey();
            if (SKIP_HEADERS.contains(name.toLowerCase())) continue;
            sb.append(" \\\n  -H '").append(esc(name + ": " + h.getValue())).append("'");
        }

        // Body
        if (msg.hasBody()) {
            String body = msg.rawBody();
            sb.append(" \\\n  -d '").append(esc(body)).append("'");
        }

        return sb.toString();
    }

    private static String esc(String s) {
        return s.replace("'", "'\\''");
    }
}
