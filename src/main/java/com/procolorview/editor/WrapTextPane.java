package com.procolorview.editor;

import javax.swing.JTextPane;
import javax.swing.plaf.ComponentUI;
import java.awt.Dimension;

/**
 * JTextPane con toggle de word-wrap cross-platform (macOS + Windows).
 *
 * Wrap ON  (default): el texto se ajusta al ancho del viewport.
 * Wrap OFF: las líneas se extienden sin cortar, aparece scrollbar horizontal.
 *
 * El truco para que no-wrap funcione correctamente en un JScrollPane es
 * que getScrollableTracksViewportWidth() retorne false Y que
 * getPreferredSize() retorne el tamaño real que el UI delegate calcula
 * (que incluye el ancho de la línea más larga).
 *
 * NO usamos modelToView/modelToView2D aquí porque causa recursión
 * durante el layout de Swing.
 */
public class WrapTextPane extends JTextPane {

    private boolean wrapEnabled = true;

    public WrapTextPane() {
        super();
    }

    public boolean isWrapEnabled() {
        return wrapEnabled;
    }

    public void setWrapEnabled(boolean enabled) {
        this.wrapEnabled = enabled;
    }

    /**
     * Wrap ON  → true  → el text pane se ajusta al ancho del viewport.
     * Wrap OFF → false → el text pane usa su ancho preferido (scroll horizontal).
     */
    @Override
    public boolean getScrollableTracksViewportWidth() {
        if (!wrapEnabled) {
            // En modo no-wrap: nunca trackear el viewport.
            // Esto permite que el JScrollPane muestre scrollbar horizontal.
            return false;
        }
        // En modo wrap: comportamiento normal (ajustar al viewport)
        return super.getScrollableTracksViewportWidth();
    }

    /**
     * En modo no-wrap, el ancho preferido debe ser el del contenido real,
     * no el del viewport. Preguntamos al UI delegate que sabe calcular
     * el tamaño basándose en la view hierarchy del documento.
     */
    @Override
    public Dimension getPreferredSize() {
        if (!wrapEnabled) {
            // Pedir al UI delegate el tamaño que necesita el contenido.
            // Esto funciona porque el UI delegate itera las views del documento
            // y calcula el ancho máximo de todas las líneas.
            ComponentUI ui = getUI();
            if (ui != null) {
                Dimension d = ui.getPreferredSize(this);
                if (d != null) {
                    return d;
                }
            }
        }
        return super.getPreferredSize();
    }

    @Override
    public boolean isFocusable() {
        return true;
    }
}
