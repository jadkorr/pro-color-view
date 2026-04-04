package com.procolorview.search;

import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Document;
import javax.swing.text.Highlighter;
import javax.swing.text.JTextComponent;
import java.awt.Color;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Motor de búsqueda + reemplazo cross-platform (macOS + Windows).
 *
 * v3.0:
 *   - Highlight visual de TODOS los matches sin mover scroll
 *   - Prev/Next selecciona match actual y hace scroll
 *   - Replace: reemplaza match actual
 *   - Replace All: reemplaza todos los matches
 *
 * FIX WINDOWS: Usa doc.getText(0, doc.getLength()) para posiciones
 * consistentes en ambas plataformas.
 */
public class SearchManager {

    private final JTextComponent editor;
    private final List<int[]> matches = new ArrayList<>();
    private int currentIndex = -1;

    // Highlight tags para poder removerlos
    private final List<Object> highlightTags = new ArrayList<>();
    private Object currentMatchTag = null;

    // Colores para los highlights de búsqueda
    private static final Color ALL_MATCH_COLOR     = new Color(255, 214, 102, 70);
    private static final Color CURRENT_MATCH_COLOR = new Color(255, 165, 0, 130);

    public SearchManager(JTextComponent editor) {
        this.editor = editor;
    }

    /**
     * Ejecuta la búsqueda. Siempre case-insensitive.
     */
    public int search(String query, boolean isRegex) {
        matches.clear();
        currentIndex = -1;

        if (query == null || query.isEmpty()) return 0;

        String text = getDocumentText();
        if (text == null || text.isEmpty()) return 0;

        try {
            Pattern pattern;
            if (isRegex) {
                pattern = Pattern.compile(query, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
            } else {
                pattern = Pattern.compile(Pattern.quote(query), Pattern.CASE_INSENSITIVE);
            }

            Matcher m = pattern.matcher(text);
            while (m.find()) {
                matches.add(new int[]{m.start(), m.end()});
            }
        } catch (Exception e) {
            return 0;
        }

        return matches.size();
    }

    /**
     * Pinta TODOS los matches con highlight visual, sin mover el scroll.
     */
    public void highlightAllMatches() {
        clearMatchHighlights();
        Highlighter hl = editor.getHighlighter();
        DefaultHighlighter.DefaultHighlightPainter allPainter =
                new DefaultHighlighter.DefaultHighlightPainter(ALL_MATCH_COLOR);

        for (int[] match : matches) {
            try {
                Object tag = hl.addHighlight(match[0], match[1], allPainter);
                highlightTags.add(tag);
            } catch (BadLocationException ignored) {}
        }
    }

    /**
     * Elimina todos los highlights de búsqueda.
     */
    public void clearMatchHighlights() {
        Highlighter hl = editor.getHighlighter();
        for (Object tag : highlightTags) {
            hl.removeHighlight(tag);
        }
        highlightTags.clear();
        if (currentMatchTag != null) {
            hl.removeHighlight(currentMatchTag);
            currentMatchTag = null;
        }
    }

    /**
     * Navega al siguiente match: lo marca con color diferente y hace scroll.
     */
    public int next() {
        if (matches.isEmpty()) return -1;

        int caretPos = editor.getCaretPosition();
        currentIndex = -1;

        for (int i = 0; i < matches.size(); i++) {
            if (matches.get(i)[0] >= caretPos) {
                currentIndex = i;
                break;
            }
        }

        if (currentIndex == -1) currentIndex = 0;

        selectMatch(currentIndex);
        return currentIndex + 1;
    }

    /**
     * Navega al match anterior.
     */
    public int prev() {
        if (matches.isEmpty()) return -1;

        int caretPos = editor.getSelectionStart();
        currentIndex = -1;

        for (int i = matches.size() - 1; i >= 0; i--) {
            if (matches.get(i)[0] < caretPos) {
                currentIndex = i;
                break;
            }
        }

        if (currentIndex == -1) currentIndex = matches.size() - 1;

        selectMatch(currentIndex);
        return currentIndex + 1;
    }

    // ── Replace ─────────────────────────────────────────────────────

    /**
     * Reemplaza el match actual y avanza al siguiente.
     * @return true si se realizó el reemplazo.
     */
    public boolean replaceCurrent(String replacement) {
        if (currentIndex < 0 || currentIndex >= matches.size()) return false;
        if (replacement == null) replacement = "";

        int[] match = matches.get(currentIndex);
        Document doc = editor.getDocument();

        try {
            int len = match[1] - match[0];
            doc.remove(match[0], len);
            doc.insertString(match[0], replacement, null);

            // Ajustar offsets de matches posteriores
            int delta = replacement.length() - len;
            for (int i = currentIndex + 1; i < matches.size(); i++) {
                matches.get(i)[0] += delta;
                matches.get(i)[1] += delta;
            }

            // Remover el match actual de la lista
            matches.remove(currentIndex);

            // Seleccionar siguiente match
            if (!matches.isEmpty()) {
                if (currentIndex >= matches.size()) currentIndex = 0;
                highlightAllMatches();
                selectMatch(currentIndex);
            } else {
                clearMatchHighlights();
                currentIndex = -1;
            }

            return true;
        } catch (BadLocationException e) {
            return false;
        }
    }

    /**
     * Reemplaza TODOS los matches.
     * @return número de reemplazos realizados.
     */
    public int replaceAll(String query, String replacement, boolean isRegex) {
        if (replacement == null) replacement = "";

        // Re-buscar para tener matches frescos
        search(query, isRegex);
        if (matches.isEmpty()) return 0;

        Document doc = editor.getDocument();
        int count = 0;

        // Reemplazar de atrás hacia adelante para mantener posiciones
        for (int i = matches.size() - 1; i >= 0; i--) {
            int[] match = matches.get(i);
            try {
                doc.remove(match[0], match[1] - match[0]);
                doc.insertString(match[0], replacement, null);
                count++;
            } catch (BadLocationException ignored) {}
        }

        clearMatchHighlights();
        matches.clear();
        currentIndex = -1;

        return count;
    }

    // ── Getters ─────────────────────────────────────────────────────

    public int totalMatches() {
        return matches.size();
    }

    public int currentIndex() {
        return currentIndex;
    }

    public String statusText() {
        if (matches.isEmpty()) return "Sin coincidencias";
        if (currentIndex < 0) return "%d encontrados".formatted(matches.size());
        return "%d/%d".formatted(currentIndex + 1, matches.size());
    }

    // ── Internos ────────────────────────────────────────────────────

    private String getDocumentText() {
        Document doc = editor.getDocument();
        try {
            return doc.getText(0, doc.getLength());
        } catch (BadLocationException e) {
            return "";
        }
    }

    /**
     * Marca el match actual con color diferente, selecciona y scrollea.
     */
    private void selectMatch(int idx) {
        if (idx < 0 || idx >= matches.size()) return;
        int[] match = matches.get(idx);

        // Repintar: todos en amarillo, el actual en naranja
        highlightAllMatches();

        Highlighter hl = editor.getHighlighter();
        if (currentMatchTag != null) {
            hl.removeHighlight(currentMatchTag);
        }
        try {
            DefaultHighlighter.DefaultHighlightPainter curPainter =
                    new DefaultHighlighter.DefaultHighlightPainter(CURRENT_MATCH_COLOR);
            currentMatchTag = hl.addHighlight(match[0], match[1], curPainter);
        } catch (BadLocationException ignored) {}

        // Seleccionar y hacer scroll
        editor.requestFocusInWindow();
        editor.select(match[0], match[1]);

        try {
            var rect = editor.modelToView2D(match[0]);
            if (rect != null) {
                editor.scrollRectToVisible(rect.getBounds());
            }
        } catch (BadLocationException ignored) {}
    }
}
