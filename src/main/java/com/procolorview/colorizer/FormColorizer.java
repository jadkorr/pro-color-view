package com.procolorview.colorizer;

import com.procolorview.theme.ProColorTheme;

import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyledDocument;

import static com.procolorview.colorizer.HttpColorizer.append;
import static com.procolorview.colorizer.HttpColorizer.style;

/**
 * Coloriza form-urlencoded (ya pre-formateado como "key = value").
 */
public final class FormColorizer {

    private FormColorizer() {}

    public static void colorize(StyledDocument doc, String formBody, ProColorTheme theme) throws Exception {
        SimpleAttributeSet keyStyle  = style(theme.formKey, true);
        SimpleAttributeSet valStyle  = style(theme.formValue, false);
        SimpleAttributeSet sepStyle  = style(theme.formSeparator, false);

        String[] lines = formBody.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            int eqIdx = line.indexOf(" = ");
            if (eqIdx > 0) {
                append(doc, line.substring(0, eqIdx), keyStyle);
                append(doc, " = ", sepStyle);
                append(doc, line.substring(eqIdx + 3), valStyle);
            } else {
                append(doc, line, valStyle);
            }
            if (i < lines.length - 1) {
                append(doc, "\n", sepStyle);
            }
        }
    }
}
