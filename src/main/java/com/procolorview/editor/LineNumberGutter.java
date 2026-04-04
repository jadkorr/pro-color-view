package com.procolorview.editor;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.Element;
import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

/**
 * Panel de números de línea que se sincroniza con el JTextPane.
 * Se usa como row header del JScrollPane para que scrollee con el editor.
 *
 * Features:
 *   - Se repinta automáticamente al cambiar el documento
 *   - Se adapta al número de dígitos (ancho dinámico)
 *   - Resalta la línea donde está el caret
 *   - Antialiased text rendering
 */
public class LineNumberGutter extends JPanel implements DocumentListener {

    private final JTextPane editor;
    private final Font font;
    private final Color fgColor;
    private final Color activeFg;
    private final Color bgColor;
    private boolean visible = true;

    public LineNumberGutter(JTextPane editor, Font font, Color fg, Color bg) {
        this.editor = editor;
        this.font = font.deriveFont(Font.PLAIN, 10f);
        this.fgColor = new Color(fg.getRed(), fg.getGreen(), fg.getBlue(), 120);
        this.activeFg = fg;
        this.bgColor = bg;

        setBackground(bgColor);
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 0, 1,
                        new Color(fg.getRed(), fg.getGreen(), fg.getBlue(), 40)),
                BorderFactory.createEmptyBorder(0, 4, 0, 6)
        ));

        editor.getDocument().addDocumentListener(this);

        // Repintar cuando el caret se mueva (resaltar línea activa)
        editor.addCaretListener(e -> repaint());
    }

    public void setGutterVisible(boolean visible) {
        this.visible = visible;
        setVisible(visible);
        revalidate();
        repaint();
    }

    public boolean isGutterVisible() {
        return visible;
    }

    @Override
    public Dimension getPreferredSize() {
        if (!visible) return new Dimension(0, 0);
        int lines = getLineCount();
        int digits = Math.max(3, String.valueOf(lines).length());
        FontMetrics fm = getFontMetrics(font);
        int width = fm.charWidth('0') * (digits + 1) + 16;
        return new Dimension(width, editor.getPreferredSize().height);
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        if (!visible) return;

        Graphics2D g2 = (Graphics2D) g;
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g2.setFont(font);

        FontMetrics fm = g2.getFontMetrics();
        Rectangle clip = g.getClipBounds();

        // Determinar líneas visibles
        int startOffset = editor.viewToModel2D(new Point(0, clip.y));
        int endOffset = editor.viewToModel2D(new Point(0, clip.y + clip.height));

        Element root = editor.getDocument().getDefaultRootElement();
        int startLine = root.getElementIndex(startOffset);
        int endLine = Math.min(root.getElementIndex(endOffset), root.getElementCount() - 1);

        // Línea activa (donde está el caret)
        int caretLine = root.getElementIndex(editor.getCaretPosition());

        for (int i = startLine; i <= endLine; i++) {
            try {
                Element lineElem = root.getElement(i);
                int lineStart = lineElem.getStartOffset();
                var rect = editor.modelToView2D(lineStart);
                if (rect == null) continue;

                String lineNum = String.valueOf(i + 1);
                int strWidth = fm.stringWidth(lineNum);
                int x = getWidth() - strWidth - 8;
                int y = (int) rect.getY() + fm.getAscent();

                // Resaltar línea activa
                g2.setColor(i == caretLine ? activeFg : fgColor);
                g2.drawString(lineNum, x, y);
            } catch (Exception ignored) {}
        }
    }

    private int getLineCount() {
        return editor.getDocument().getDefaultRootElement().getElementCount();
    }

    // ── DocumentListener ────────────────────────────────────────────

    @Override public void insertUpdate(DocumentEvent e) { repaintLater(); }
    @Override public void removeUpdate(DocumentEvent e) { repaintLater(); }
    @Override public void changedUpdate(DocumentEvent e) { repaintLater(); }

    private void repaintLater() {
        SwingUtilities.invokeLater(() -> {
            revalidate();
            repaint();
        });
    }
}
