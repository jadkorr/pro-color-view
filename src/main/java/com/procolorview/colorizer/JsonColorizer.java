package com.procolorview.colorizer;

import com.procolorview.theme.ProColorTheme;

import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyledDocument;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.procolorview.colorizer.HttpColorizer.append;
import static com.procolorview.colorizer.HttpColorizer.style;

/**
 * Coloriza JSON token por token dentro de un StyledDocument.
 */
public final class JsonColorizer {

    private JsonColorizer() {}

    private static final Pattern TOKEN_RE = Pattern.compile(
            "(\"(?:\\\\.|[^\"\\\\])*\")(\\s*:)?|(-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?)|\\b(true|false|null)\\b"
    );

    public static void colorize(StyledDocument doc, String json, ProColorTheme theme) throws Exception {
        SimpleAttributeSet keyStyle     = style(theme.jsonKey, true);
        SimpleAttributeSet stringStyle  = style(theme.jsonString, false);
        SimpleAttributeSet numberStyle  = style(theme.jsonNumber, false);
        SimpleAttributeSet literalStyle = style(theme.jsonLiteral, true);
        SimpleAttributeSet bracketStyle = style(theme.jsonBracket, false);

        Matcher m = TOKEN_RE.matcher(json);
        int cursor = 0;

        while (m.find()) {
            if (m.start() > cursor) {
                append(doc, json.substring(cursor, m.start()), bracketStyle);
            }

            if (m.group(2) != null) {
                append(doc, m.group(1), keyStyle);
                append(doc, m.group(2), bracketStyle);
            } else if (m.group(1) != null) {
                append(doc, m.group(1), stringStyle);
            } else if (m.group(3) != null) {
                append(doc, m.group(3), numberStyle);
            } else if (m.group(4) != null) {
                append(doc, m.group(4), literalStyle);
            }

            cursor = m.end();
        }

        if (cursor < json.length()) {
            append(doc, json.substring(cursor), bracketStyle);
        }
    }
}
