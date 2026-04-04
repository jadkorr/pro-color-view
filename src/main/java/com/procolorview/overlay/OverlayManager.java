package com.procolorview.overlay;

import com.procolorview.theme.ProColorTheme;

import javax.swing.text.*;
import java.awt.Color;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Aplica overlays sobre el StyledDocument después del renderizado:
 *
 *   - HIGHLIGHT: Agrega un fondo de color a las palabras matcheadas.
 *     Los usuarios pueden definir palabras separadas por comas.
 *     Colores: amarillo, cyan, verde, rosa (rotan).
 *
 *   - BLUR: Oculta el texto sensible poniendo el foreground igual al
 *     background y un fondo rayado. Al seleccionar el texto se revela.
 *     Útil para tokens, passwords, API keys, etc.
 */
public final class OverlayManager {

    private OverlayManager() {}

    // Colores de highlight que rotan por palabra
    private static final Color[] HIGHLIGHT_COLORS_DARK = {
        new Color(255, 214, 102, 70),  // amarillo
        new Color(124, 211, 255, 60),  // cyan
        new Color(134, 239, 172, 60),  // verde
        new Color(244, 114, 182, 60),  // rosa
    };

    private static final Color[] HIGHLIGHT_COLORS_LIGHT = {
        new Color(255, 235, 59, 90),   // amarillo
        new Color(100, 181, 246, 80),  // azul
        new Color(129, 199, 132, 80),  // verde
        new Color(240, 98, 146, 70),   // rosa
    };

    // Color de blur — negro sólido para ocultar completamente
    private static final Color BLUR_BG_DARK  = new Color(0, 0, 0);
    private static final Color BLUR_BG_LIGHT = new Color(0, 0, 0);

    /**
     * Aplica highlights a las palabras especificadas (comma-separated).
     * Cada palabra diferente obtiene un color distinto (rotando).
     */
    public static void applyHighlights(StyledDocument doc, String wordsCSV, ProColorTheme theme) {
        if (wordsCSV == null || wordsCSV.isBlank()) return;

        String[] words = wordsCSV.split(",");
        Color[] palette = theme.isDark() ? HIGHLIGHT_COLORS_DARK : HIGHLIGHT_COLORS_LIGHT;

        String text;
        try {
            text = doc.getText(0, doc.getLength());
        } catch (BadLocationException e) {
            return;
        }

        int colorIdx = 0;
        for (String word : words) {
            String trimmed = word.strip();
            if (trimmed.isEmpty()) continue;

            Color bgColor = palette[colorIdx % palette.length];
            colorIdx++;

            try {
                Pattern p = Pattern.compile(Pattern.quote(trimmed), Pattern.CASE_INSENSITIVE);
                Matcher m = p.matcher(text);

                while (m.find()) {
                    SimpleAttributeSet attrs = new SimpleAttributeSet();
                    StyleConstants.setBackground(attrs, bgColor);
                    StyleConstants.setBold(attrs, true);
                    // Aplicar sin reemplazar los atributos existentes (merge)
                    doc.setCharacterAttributes(m.start(), m.end() - m.start(), attrs, false);
                }
            } catch (Exception ignored) {}
        }
    }

    /**
     * Aplica blur a las palabras especificadas (comma-separated).
     * El texto se vuelve "invisible" (foreground = background blur) pero
     * al seleccionarlo se ve gracias al selectedTextColor del editor.
     */
    public static void applyBlur(StyledDocument doc, String wordsCSV, ProColorTheme theme) {
        if (wordsCSV == null || wordsCSV.isBlank()) return;

        String[] words = wordsCSV.split(",");
        Color blurBg = theme.isDark() ? BLUR_BG_DARK : BLUR_BG_LIGHT;
        // Foreground igual al blur background para "esconder" el texto
        Color blurFg = blurBg;

        String text;
        try {
            text = doc.getText(0, doc.getLength());
        } catch (BadLocationException e) {
            return;
        }

        for (String word : words) {
            String trimmed = word.strip();
            if (trimmed.isEmpty()) continue;

            try {
                Pattern p = Pattern.compile(Pattern.quote(trimmed), Pattern.CASE_INSENSITIVE);
                Matcher m = p.matcher(text);

                while (m.find()) {
                    SimpleAttributeSet attrs = new SimpleAttributeSet();
                    StyleConstants.setBackground(attrs, blurBg);
                    StyleConstants.setForeground(attrs, blurFg);
                    doc.setCharacterAttributes(m.start(), m.end() - m.start(), attrs, false);
                }
            } catch (Exception ignored) {}
        }
    }
}
