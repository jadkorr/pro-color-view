package com.procolorview.colorizer;

import com.procolorview.theme.ProColorTheme;
import com.procolorview.util.ColorConfig;

import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyledDocument;

import static com.procolorview.colorizer.HttpColorizer.append;
import static com.procolorview.colorizer.HttpColorizer.style;

/**
 * Colorizes form-urlencoded body in raw format: key=value&key2=value2
 * Colors are configurable via ColorConfig and persisted per project.
 */
public final class FormColorizer {

    private FormColorizer() {}

    public static void colorize(StyledDocument doc, String formBody, ProColorTheme theme) throws Exception {
        boolean dark = theme.isDark();
        SimpleAttributeSet keyStyle  = style(ColorConfig.paramKey(dark), true);
        SimpleAttributeSet valStyle  = style(ColorConfig.paramValue(dark), false);
        SimpleAttributeSet eqStyle   = style(ColorConfig.paramEqual(dark), false);
        SimpleAttributeSet sepStyle  = style(ColorConfig.paramSep(dark), false);

        // Handle both raw format (key=val&key2=val2) and pretty format (key = val\nkey2 = val2)
        if (formBody.contains("&") || !formBody.contains("\n")) {
            // Raw URL-encoded format
            colorizeRaw(doc, formBody, keyStyle, valStyle, eqStyle, sepStyle);
        } else {
            // Pretty format (legacy, one param per line)
            colorizePretty(doc, formBody, keyStyle, valStyle, eqStyle, sepStyle);
        }
    }

    private static void colorizeRaw(StyledDocument doc, String body,
            SimpleAttributeSet keyStyle, SimpleAttributeSet valStyle,
            SimpleAttributeSet eqStyle, SimpleAttributeSet sepStyle) throws Exception {
        String[] pairs = body.split("&");
        for (int i = 0; i < pairs.length; i++) {
            String pair = pairs[i];
            int eqIdx = pair.indexOf('=');
            if (eqIdx >= 0) {
                append(doc, pair.substring(0, eqIdx), keyStyle);
                append(doc, "=", eqStyle);
                append(doc, pair.substring(eqIdx + 1), valStyle);
            } else {
                // No = sign, just a key
                append(doc, pair, keyStyle);
            }
            if (i < pairs.length - 1) {
                append(doc, "&", sepStyle);
            }
        }
    }

    private static void colorizePretty(StyledDocument doc, String body,
            SimpleAttributeSet keyStyle, SimpleAttributeSet valStyle,
            SimpleAttributeSet eqStyle, SimpleAttributeSet sepStyle) throws Exception {
        String[] lines = body.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            int eqIdx = line.indexOf(" = ");
            if (eqIdx > 0) {
                append(doc, line.substring(0, eqIdx), keyStyle);
                append(doc, " = ", eqStyle);
                append(doc, line.substring(eqIdx + 3), valStyle);
            } else {
                // Try raw = format
                int rawEq = line.indexOf('=');
                if (rawEq > 0) {
                    append(doc, line.substring(0, rawEq), keyStyle);
                    append(doc, "=", eqStyle);
                    append(doc, line.substring(rawEq + 1), valStyle);
                } else {
                    append(doc, line, valStyle);
                }
            }
            if (i < lines.length - 1) {
                append(doc, "\n", sepStyle);
            }
        }
    }
}
