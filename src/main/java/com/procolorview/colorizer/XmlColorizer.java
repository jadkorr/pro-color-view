package com.procolorview.colorizer;

import com.procolorview.theme.ProColorTheme;

import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyledDocument;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.procolorview.colorizer.HttpColorizer.append;
import static com.procolorview.colorizer.HttpColorizer.style;

/**
 * Coloriza XML/HTML dentro de un StyledDocument.
 */
public final class XmlColorizer {

    private XmlColorizer() {}

    private static final Pattern XML_TOKEN = Pattern.compile(
            "(<!--[\\s\\S]*?-->)" +
            "|(</?[^>]+>)" +
            "|([^<]+)"
    );

    private static final Pattern TAG_INNER = Pattern.compile(
            "(</?)(\\w[\\w:.\\-]*)" +
            "([^>]*?)" +
            "(/?>)"
    );

    private static final Pattern ATTR = Pattern.compile(
            "(\\w[\\w:.\\-]*)\\s*=\\s*(\"[^\"]*\"|'[^']*'|\\S+)"
    );

    public static void colorize(StyledDocument doc, String xml, ProColorTheme theme) throws Exception {
        SimpleAttributeSet tagStyle       = style(theme.xmlTag, true);
        SimpleAttributeSet attrNameStyle  = style(theme.xmlAttrName, false);
        SimpleAttributeSet attrValueStyle = style(theme.xmlAttrValue, false);
        SimpleAttributeSet contentStyle   = style(theme.xmlContent, false);
        SimpleAttributeSet commentStyle   = style(theme.xmlComment, false);
        SimpleAttributeSet bracketStyle   = style(theme.xmlTag, false);

        Matcher m = XML_TOKEN.matcher(xml);

        while (m.find()) {
            if (m.group(1) != null) {
                append(doc, m.group(1), commentStyle);
            } else if (m.group(2) != null) {
                colorizeTag(doc, m.group(2), tagStyle, attrNameStyle, attrValueStyle, bracketStyle);
            } else if (m.group(3) != null) {
                append(doc, m.group(3), contentStyle);
            }
        }
    }

    private static void colorizeTag(StyledDocument doc, String tag,
                                     SimpleAttributeSet tagStyle,
                                     SimpleAttributeSet attrNameStyle,
                                     SimpleAttributeSet attrValueStyle,
                                     SimpleAttributeSet bracketStyle) throws Exception {
        Matcher tm = TAG_INNER.matcher(tag);
        if (tm.matches()) {
            append(doc, tm.group(1), bracketStyle);
            append(doc, tm.group(2), tagStyle);

            String attrsStr = tm.group(3);
            if (attrsStr != null && !attrsStr.isBlank()) {
                Matcher am = ATTR.matcher(attrsStr);
                int cursor = 0;
                while (am.find()) {
                    if (am.start() > cursor) {
                        append(doc, attrsStr.substring(cursor, am.start()), bracketStyle);
                    }
                    append(doc, am.group(1), attrNameStyle);
                    append(doc, "=", bracketStyle);
                    append(doc, am.group(2), attrValueStyle);
                    cursor = am.end();
                }
                if (cursor < attrsStr.length()) {
                    append(doc, attrsStr.substring(cursor), bracketStyle);
                }
            }

            append(doc, tm.group(4), bracketStyle);
        } else {
            append(doc, tag, tagStyle);
        }
    }
}
