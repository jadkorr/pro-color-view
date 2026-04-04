package com.procolorview.colorizer;

import com.procolorview.parser.HttpMessageParser;
import com.procolorview.parser.ParsedHttpMessage;
import com.procolorview.theme.ProColorTheme;

import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.Color;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Coloriza un mensaje HTTP parseado dentro de un StyledDocument.
 *
 * Headers: nombre en un color, valor en otro color uniforme.
 * Dentro del valor, los atributos separados por "=" se colorean:
 *   key=value → key en un color, = en separador, value en otro color.
 *   Ej: "max-age=3600; path=/; HttpOnly"
 *       → max-age(key) =(sep) 3600(value) ;(sep) path(key) =(sep) /(value) ...
 */
public final class HttpColorizer {

    private HttpColorizer() {}

    private static final Set<String> SENSITIVE_HEADERS = Set.of(
            "authorization", "cookie", "set-cookie", "content-type",
            "host", "x-api-key", "x-csrf-token", "x-forwarded-for",
            "proxy-authorization", "www-authenticate"
    );

    private static final Pattern REQUEST_PATTERN =
            Pattern.compile("^([A-Z]{3,10})\\s+(\\S+)\\s+(HTTP/\\d(?:\\.\\d)?)$");

    private static final Pattern RESPONSE_PATTERN =
            Pattern.compile("^(HTTP/\\d(?:\\.\\d)?)\\s+(\\d{3})(.*)$");

    // Regex para detectar key=value dentro de valores de headers.
    // Captura: key (grupo 1), = (literal), value (grupo 2)
    // Value termina en ; o fin de string
    private static final Pattern ATTR_PATTERN =
            Pattern.compile("([\\w.\\-]+)=(\"[^\"]*\"|[^;,\\s]*)");

    public static void render(StyledDocument doc, ParsedHttpMessage msg, ProColorTheme theme) {
        render(doc, msg, theme, true);
    }

    /**
     * Renderiza el mensaje HTTP con syntax highlighting.
     * @param pretty true = body formateado (beautify), false = body raw (minify)
     */
    public static void render(StyledDocument doc, ParsedHttpMessage msg, ProColorTheme theme, boolean pretty) {
        try {
            doc.remove(0, doc.getLength());
            renderStartLine(doc, msg, theme);
            renderHeaders(doc, msg, theme);
            renderBody(doc, msg, theme, pretty);
        } catch (Exception e) {
            try {
                doc.remove(0, doc.getLength());
                append(doc, msg.rebuild(), style(theme.fg, false));
            } catch (Exception ignored) {}
        }
    }

    // ── Start line ──────────────────────────────────────────────────

    private static void renderStartLine(StyledDocument doc, ParsedHttpMessage msg, ProColorTheme theme) throws Exception {
        String line = msg.startLine();
        if (line.isEmpty()) return;

        if (HttpMessageParser.isRequestLine(line)) {
            Matcher m = REQUEST_PATTERN.matcher(line);
            if (m.matches()) {
                append(doc, m.group(1), style(theme.methodColor, true));
                append(doc, " ", style(theme.fg, false));
                append(doc, m.group(2), style(theme.urlColor, false));
                append(doc, " ", style(theme.fg, false));
                append(doc, m.group(3), style(theme.versionColor, false));
            } else {
                append(doc, line, style(theme.methodColor, true));
            }
        } else {
            Matcher m = RESPONSE_PATTERN.matcher(line);
            if (m.matches()) {
                int statusCode = Integer.parseInt(m.group(2));
                Color statusColor = theme.getStatusColor(statusCode);

                append(doc, m.group(1), style(theme.versionColor, false));
                append(doc, " ", style(theme.fg, false));
                append(doc, m.group(2), style(statusColor, true));
                if (!m.group(3).isEmpty()) {
                    append(doc, m.group(3), style(statusColor, true));
                }
            } else {
                append(doc, line, style(theme.status2xx, true));
            }
        }
        append(doc, "\n", style(theme.fg, false));
    }

    // ── Headers ─────────────────────────────────────────────────────

    private static void renderHeaders(StyledDocument doc, ParsedHttpMessage msg, ProColorTheme theme) throws Exception {
        SimpleAttributeSet nameStyle = style(theme.headerName, true);
        SimpleAttributeSet metaStyle = style(theme.headerMeta, true);
        SimpleAttributeSet defStyle  = style(theme.fg, false);

        for (Map.Entry<String, String> header : msg.headers()) {
            String name  = header.getKey();
            String value = header.getValue();

            boolean isSensitive = SENSITIVE_HEADERS.contains(name.toLowerCase());
            append(doc, name, isSensitive ? metaStyle : nameStyle);
            append(doc, ": ", defStyle);

            // Colorizar valor: color uniforme + atributos key=value resaltados
            renderHeaderValue(doc, value, theme);
            append(doc, "\n", defStyle);
        }
    }

    /**
     * Renderiza el valor de un header con color uniforme base.
     * Dentro del valor, detecta patrones key=value (separados por ; o ,)
     * y los colorea: key en cyan, = en gris, value en verde.
     */
    private static void renderHeaderValue(StyledDocument doc, String value, ProColorTheme theme) throws Exception {
        SimpleAttributeSet valueStyle = style(theme.headerValue, false);
        SimpleAttributeSet attrKey    = style(theme.jsonKey, true);      // cyan bold
        SimpleAttributeSet attrSep    = style(theme.bodyHint, false);    // gris
        SimpleAttributeSet attrVal    = style(theme.jsonString, false);  // verde

        // Buscar patrones key=value
        Matcher m = ATTR_PATTERN.matcher(value);
        int cursor = 0;
        boolean foundAttr = false;

        while (m.find()) {
            foundAttr = true;

            // Texto antes del atributo (separadores ;, espacios, etc.)
            if (m.start() > cursor) {
                append(doc, value.substring(cursor, m.start()), valueStyle);
            }

            // key
            append(doc, m.group(1), attrKey);
            // =
            append(doc, "=", attrSep);
            // value
            append(doc, m.group(2), attrVal);

            cursor = m.end();
        }

        // Resto del texto (o todo si no hubo atributos)
        if (cursor < value.length()) {
            append(doc, value.substring(cursor), valueStyle);
        }

        // Si no hubo ningún atributo, ya se escribió todo como valueStyle
    }

    // ── Body ────────────────────────────────────────────────────────

    private static void renderBody(StyledDocument doc, ParsedHttpMessage msg, ProColorTheme theme) throws Exception {
        renderBody(doc, msg, theme, true);
    }

    private static void renderBody(StyledDocument doc, ParsedHttpMessage msg, ProColorTheme theme, boolean pretty) throws Exception {
        if (!msg.hasBody()) return;

        append(doc, "\n", style(theme.fg, false));

        String body;
        if (pretty) {
            body = msg.displayBody();
        } else {
            // Minificar activamente (no solo usar rawBody, que puede venir ya formateado)
            body = msg.rawBody();
            if (msg.bodyType() == ParsedHttpMessage.BodyType.JSON) {
                body = HttpMessageParser.minifyJson(body);
            }
        }
        switch (msg.bodyType()) {
            case JSON -> JsonColorizer.colorize(doc, body, theme);
            case XML, HTML -> XmlColorizer.colorize(doc, body, theme);
            case JAVASCRIPT -> JsColorizer.colorize(doc, body, theme);
            case FORM -> FormColorizer.colorize(doc, body, theme);
            default -> append(doc, body, style(theme.bodyHint, false));
        }
    }

    // ── Utilidades (package-private) ────────────────────────────────

    static SimpleAttributeSet style(Color fg, boolean bold) {
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setForeground(attrs, fg);
        StyleConstants.setBold(attrs, bold);
        return attrs;
    }

    static void append(StyledDocument doc, String text, SimpleAttributeSet style) throws Exception {
        doc.insertString(doc.getLength(), text, style);
    }
}
