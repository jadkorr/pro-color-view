package com.procolorview.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extrae URLs, paths relativos, endpoints y subdominios del texto HTTP.
 *
 * Categoriza los resultados por tipo:
 * - Absolute URLs (http/https)
 * - Relative Paths (/api/v1/...)
 * - JS Endpoints (fetch, axios, XMLHttpRequest references)
 * - Subdomains
 * - URL Parameters (redirect=, callback=, next=)
 * - HTML Resources (src=, href=, action=)
 * - Comments (URLs inside <!-- --> o // /＊ ＊/)
 */
public final class LinkFinder {

    private LinkFinder() {}

    public record Link(String type, String url, int line) {}

    // ── Patterns ───────────────────────────────────────────────────

    // Absolute URLs
    private static final Pattern ABSOLUTE_URL =
            Pattern.compile("https?://[^\\s'\"<>\\)\\]}{,;]+");

    // Relative paths: /path/to/resource (at least 2 segments or file extension)
    private static final Pattern RELATIVE_PATH =
            Pattern.compile("(?<=[\"'`=\\s(,])(/[a-zA-Z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+)(?=[\"'`\\s)>,;])");

    // JS endpoints: string literals in JS contexts
    private static final Pattern JS_STRING_ENDPOINT =
            Pattern.compile("(?:fetch|axios[.a-z]*|\\$\\.(?:get|post|put|delete|ajax)|XMLHttpRequest|http\\.(?:get|post|put|patch|delete)|request|urllib)\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]");

    // JS template literal endpoints
    private static final Pattern JS_TEMPLATE_URL =
            Pattern.compile("(?:fetch|axios|request)\\s*\\(\\s*`([^`]+)`");

    // HTML attribute URLs: src, href, action, data-url, formaction
    private static final Pattern HTML_ATTR_URL =
            Pattern.compile("(?i)(?:src|href|action|formaction|data-url|data-href|poster|cite|codebase|background)\\s*=\\s*['\"]([^'\"]+)['\"]");

    // URL parameters containing URLs
    private static final Pattern URL_PARAM_WITH_URL =
            Pattern.compile("(?i)(?:redirect|redirect_uri|redirect_url|return|return_url|next|callback|url|uri|link|goto|target|dest|destination|continue|forward|rurl|r_url)\\s*=\\s*([^&\\s'\"]+)");

    // Subdomains from URLs and text
    private static final Pattern SUBDOMAIN =
            Pattern.compile("(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.){2,}[a-zA-Z]{2,}");

    // JS object paths: {url: "/api/...", path: "/endpoint/..."}
    private static final Pattern JS_OBJECT_PATH =
            Pattern.compile("(?i)(?:url|path|endpoint|api|uri|href|route|base_?url)\\s*[=:]\\s*['\"]([^'\"]+)['\"]");

    // Comment URLs (inside HTML/JS comments)
    private static final Pattern COMMENT_URL =
            Pattern.compile("(?://|/\\*|<!--)[^\\n]*?(https?://[^\\s'\"<>*/)]+|/[a-zA-Z][a-zA-Z0-9/._-]{3,})");

    // GraphQL / API endpoints
    private static final Pattern GRAPHQL_ENDPOINT =
            Pattern.compile("(?i)(?:query|mutation|subscription)\\s+\\w+");

    // WebSocket URLs
    private static final Pattern WEBSOCKET_URL =
            Pattern.compile("wss?://[^\\s'\"<>)\\]}{,;]+");

    // ── Public API ─────────────────────────────────────────────────

    /**
     * Escanea el texto y retorna todos los links/paths encontrados,
     * deduplicados y categorizados.
     */
    public static List<Link> scan(String text) {
        List<Link> results = new ArrayList<>();
        if (text == null || text.isEmpty()) return results;

        String[] lines = text.split("\n", -1);

        // Usar sets para deduplicar URLs dentro de cada categoría
        Set<String> seenAbsolute = new LinkedHashSet<>();
        Set<String> seenRelative = new LinkedHashSet<>();
        Set<String> seenJsEndpoint = new LinkedHashSet<>();
        Set<String> seenHtmlAttr = new LinkedHashSet<>();
        Set<String> seenUrlParam = new LinkedHashSet<>();
        Set<String> seenSubdomain = new LinkedHashSet<>();
        Set<String> seenComment = new LinkedHashSet<>();
        Set<String> seenWs = new LinkedHashSet<>();
        Set<String> seenJsObject = new LinkedHashSet<>();

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            int lineNum = i + 1;

            // WebSocket URLs
            extract(WEBSOCKET_URL, line, "WebSocket", lineNum, results, seenWs, 0);

            // Absolute URLs
            extract(ABSOLUTE_URL, line, "Absolute URL", lineNum, results, seenAbsolute, 0);

            // HTML attribute URLs
            extract(HTML_ATTR_URL, line, "HTML Resource", lineNum, results, seenHtmlAttr, 1);

            // JS fetch/axios/XHR endpoints
            extract(JS_STRING_ENDPOINT, line, "JS Endpoint", lineNum, results, seenJsEndpoint, 1);
            extract(JS_TEMPLATE_URL, line, "JS Endpoint", lineNum, results, seenJsEndpoint, 1);

            // JS object paths
            extract(JS_OBJECT_PATH, line, "JS Object Path", lineNum, results, seenJsObject, 1);

            // URL params with URLs
            extract(URL_PARAM_WITH_URL, line, "URL Parameter", lineNum, results, seenUrlParam, 1);

            // Relative paths (only if looks like a real path)
            Matcher relMatcher = RELATIVE_PATH.matcher(line);
            while (relMatcher.find()) {
                String path = relMatcher.group(1);
                // Filtrar paths demasiado cortos o comunes
                if (isValidRelativePath(path) && seenRelative.add(path)) {
                    results.add(new Link("Relative Path", path, lineNum));
                }
            }

            // Comment URLs
            extract(COMMENT_URL, line, "Comment URL", lineNum, results, seenComment, 0);
        }

        // Subdomains (scan full text, extract unique)
        Matcher subMatcher = SUBDOMAIN.matcher(text);
        while (subMatcher.find()) {
            String domain = subMatcher.group().toLowerCase();
            // Filtrar dominios comunes/genéricos
            if (!isBoringDomain(domain) && seenSubdomain.add(domain)) {
                // Encontrar en qué línea está
                int lineNum = findLineNumber(text, subMatcher.start());
                results.add(new Link("Subdomain", domain, lineNum));
            }
        }

        return results;
    }

    private static void extract(Pattern pattern, String line, String type,
                                int lineNum, List<Link> results,
                                Set<String> seen, int group) {
        Matcher m = pattern.matcher(line);
        while (m.find()) {
            String val = cleanUrl(m.group(group));
            if (val != null && !val.isEmpty() && seen.add(val)) {
                results.add(new Link(type, val, lineNum));
            }
        }
    }

    // ── Formatting ─────────────────────────────────────────────────

    /**
     * Formatea los resultados como texto legible agrupado por categoría.
     */
    public static String format(List<Link> links) {
        if (links.isEmpty()) return "No links/endpoints found.";

        // Agrupar por tipo
        Map<String, List<Link>> grouped = new LinkedHashMap<>();
        for (Link l : links) {
            grouped.computeIfAbsent(l.type(), k -> new ArrayList<>()).add(l);
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Found %d unique link(s):\n", links.size()));
        sb.append("=".repeat(70)).append("\n\n");

        for (Map.Entry<String, List<Link>> entry : grouped.entrySet()) {
            sb.append("[").append(entry.getKey()).append("] (").append(entry.getValue().size()).append(")\n");
            sb.append("-".repeat(40)).append("\n");
            for (Link l : entry.getValue()) {
                sb.append(String.format("  Line %-5d | %s\n", l.line(), l.url()));
            }
            sb.append("\n");
        }

        return sb.toString();
    }

    /**
     * Retorna solo las URLs/paths limpias, una por línea (para copiar a herramientas).
     */
    public static String formatRaw(List<Link> links) {
        StringBuilder sb = new StringBuilder();
        Set<String> unique = new LinkedHashSet<>();
        for (Link l : links) {
            if (unique.add(l.url())) {
                sb.append(l.url()).append("\n");
            }
        }
        return sb.toString();
    }

    /**
     * Retorna solo paths relativos (ideal para fuzzing con ffuf/dirsearch).
     */
    public static String formatPaths(List<Link> links) {
        StringBuilder sb = new StringBuilder();
        Set<String> unique = new LinkedHashSet<>();
        for (Link l : links) {
            if (("Relative Path".equals(l.type()) || "JS Endpoint".equals(l.type())
                    || "JS Object Path".equals(l.type()))
                    && unique.add(l.url())) {
                sb.append(l.url()).append("\n");
            }
        }
        return sb.toString();
    }

    // ── Helpers ─────────────────────────────────────────────────────

    private static String cleanUrl(String url) {
        if (url == null) return null;
        // Quitar trailing punctuation
        url = url.replaceAll("[.,;:!?)\\]}>]+$", "");
        // Quitar comillas
        url = url.replaceAll("^['\"`]+|['\"`]+$", "");
        return url.isEmpty() ? null : url;
    }

    private static boolean isValidRelativePath(String path) {
        if (path == null || path.length() < 3) return false;
        // Filtrar paths con solo barras o demasiado simples
        if (path.equals("/") || path.equals("//")) return false;
        // Debe tener al menos una letra
        if (!path.matches(".*/[a-zA-Z].*")) return false;
        // Filtrar CSS/formatting paths comunes
        if (path.matches("/[0-9]+px$|/[0-9]+%$|/\\*.*")) return false;
        return true;
    }

    private static boolean isBoringDomain(String domain) {
        // Ignorar dominios comunes que no aportan valor en pentesting
        return domain.endsWith(".w3.org")
                || domain.endsWith(".schema.org")
                || domain.endsWith(".xmlsoap.org")
                || domain.endsWith(".example.com")
                || domain.equals("www.w3.org")
                || domain.endsWith(".dtd");
    }

    private static int findLineNumber(String text, int charIndex) {
        int line = 1;
        for (int i = 0; i < charIndex && i < text.length(); i++) {
            if (text.charAt(i) == '\n') line++;
        }
        return line;
    }
}
