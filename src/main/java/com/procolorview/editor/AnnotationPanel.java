package com.procolorview.editor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Line2D;
import java.awt.geom.Path2D;
import java.awt.geom.Rectangle2D;
import java.util.ArrayList;
import java.util.List;

/**
 * Panel transparente que permite dibujar anotaciones (rectángulos, flechas)
 * sobre el contenido de la ventana Snap para capturas de screenshot.
 *
 * Modos:
 *   - NONE: sin dibujo, click-through
 *   - RECT: dibujar rectángulos
 *   - ARROW: dibujar flechas
 *
 * Cada anotación se puede deshacer con Ctrl+Z o eliminarse todas con "Clear".
 */
public class AnnotationPanel extends JPanel {

    public enum Tool { NONE, RECT, ARROW }

    private Tool currentTool = Tool.NONE;
    private Color annotationColor = new Color(255, 60, 60);  // rojo por defecto
    private float strokeWidth = 2.5f;

    // Anotaciones guardadas
    private final List<Annotation> annotations = new ArrayList<>();

    // Estado de dibujo actual
    private Point dragStart;
    private Point dragEnd;
    private boolean dragging = false;

    /** Sealed record-like base for annotations */
    private static abstract class Annotation {
        final Color color;
        final float stroke;
        Annotation(Color color, float stroke) { this.color = color; this.stroke = stroke; }
        abstract void paint(Graphics2D g2);
    }

    private static class RectAnnotation extends Annotation {
        final Rectangle2D rect;
        RectAnnotation(Rectangle2D rect, Color color, float stroke) {
            super(color, stroke);
            this.rect = rect;
        }
        @Override
        void paint(Graphics2D g2) {
            g2.setColor(color);
            g2.setStroke(new BasicStroke(stroke));
            g2.draw(rect);
        }
    }

    private static class ArrowAnnotation extends Annotation {
        final int x1, y1, x2, y2;
        ArrowAnnotation(int x1, int y1, int x2, int y2, Color color, float stroke) {
            super(color, stroke);
            this.x1 = x1; this.y1 = y1; this.x2 = x2; this.y2 = y2;
        }
        @Override
        void paint(Graphics2D g2) {
            g2.setColor(color);
            g2.setStroke(new BasicStroke(stroke));
            g2.drawLine(x1, y1, x2, y2);
            drawArrowHead(g2, x1, y1, x2, y2, stroke);
        }
    }

    public AnnotationPanel() {
        setOpaque(false);
        setLayout(null);
        setCursor(Cursor.getDefaultCursor());

        MouseAdapter ma = new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (currentTool == Tool.NONE) return;
                dragStart = e.getPoint();
                dragEnd = e.getPoint();
                dragging = true;
            }

            @Override
            public void mouseDragged(MouseEvent e) {
                if (!dragging || currentTool == Tool.NONE) return;
                dragEnd = e.getPoint();
                repaint();
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (!dragging || currentTool == Tool.NONE) return;
                dragEnd = e.getPoint();
                dragging = false;

                // Crear anotación si tiene tamaño mínimo
                int dx = Math.abs(dragEnd.x - dragStart.x);
                int dy = Math.abs(dragEnd.y - dragStart.y);
                if (dx > 3 || dy > 3) {
                    if (currentTool == Tool.RECT) {
                        int rx = Math.min(dragStart.x, dragEnd.x);
                        int ry = Math.min(dragStart.y, dragEnd.y);
                        annotations.add(new RectAnnotation(
                                new Rectangle2D.Double(rx, ry, dx, dy),
                                annotationColor, strokeWidth));
                    } else if (currentTool == Tool.ARROW) {
                        annotations.add(new ArrowAnnotation(
                                dragStart.x, dragStart.y, dragEnd.x, dragEnd.y,
                                annotationColor, strokeWidth));
                    }
                }
                dragStart = null;
                dragEnd = null;
                repaint();
            }
        };

        addMouseListener(ma);
        addMouseMotionListener(ma);

        // Undo con Ctrl+Z
        getInputMap(WHEN_IN_FOCUSED_WINDOW).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_Z, Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()),
                "undoAnnotation");
        getActionMap().put("undoAnnotation", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                undoLast();
            }
        });
    }

    // ── API pública ──────────────────────────────────────────────────

    public void setTool(Tool tool) {
        this.currentTool = tool;
        // Cambiar cursor según herramienta
        if (tool == Tool.NONE) {
            setCursor(Cursor.getDefaultCursor());
        } else {
            setCursor(Cursor.getPredefinedCursor(Cursor.CROSSHAIR_CURSOR));
        }
        repaint();
    }

    public Tool getTool() {
        return currentTool;
    }

    public void setAnnotationColor(Color c) {
        this.annotationColor = c;
    }

    public Color getAnnotationColor() {
        return annotationColor;
    }

    public void setStrokeWidth(float w) {
        this.strokeWidth = w;
    }

    public void clearAll() {
        annotations.clear();
        repaint();
    }

    public void undoLast() {
        if (!annotations.isEmpty()) {
            annotations.remove(annotations.size() - 1);
            repaint();
        }
    }

    public boolean hasAnnotations() {
        return !annotations.isEmpty();
    }

    // ── Painting ─────────────────────────────────────────────────────

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        // Dibujar anotaciones guardadas
        for (Annotation ann : annotations) {
            ann.paint(g2);
        }

        // Dibujar anotación en progreso (preview)
        if (dragging && dragStart != null && dragEnd != null) {
            g2.setColor(annotationColor);
            g2.setStroke(new BasicStroke(strokeWidth, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND,
                    0, new float[]{6, 4}, 0)); // dashed preview

            if (currentTool == Tool.RECT) {
                int rx = Math.min(dragStart.x, dragEnd.x);
                int ry = Math.min(dragStart.y, dragEnd.y);
                int rw = Math.abs(dragEnd.x - dragStart.x);
                int rh = Math.abs(dragEnd.y - dragStart.y);
                g2.drawRect(rx, ry, rw, rh);
            } else if (currentTool == Tool.ARROW) {
                g2.drawLine(dragStart.x, dragStart.y, dragEnd.x, dragEnd.y);
                // Preview arrowhead solid
                g2.setStroke(new BasicStroke(strokeWidth));
                drawArrowHead(g2, dragStart.x, dragStart.y, dragEnd.x, dragEnd.y, strokeWidth);
            }
        }

        g2.dispose();
    }

    // ── Flecha helper ────────────────────────────────────────────────

    /**
     * Dibuja la punta de flecha en (x2,y2) apuntando desde (x1,y1).
     */
    private static void drawArrowHead(Graphics2D g2, int x1, int y1, int x2, int y2, float stroke) {
        double dx = x2 - x1;
        double dy = y2 - y1;
        double len = Math.sqrt(dx * dx + dy * dy);
        if (len < 1) return;

        double arrowSize = Math.max(10, stroke * 5);
        double angle = Math.atan2(dy, dx);

        Path2D arrow = new Path2D.Double();
        arrow.moveTo(x2, y2);
        arrow.lineTo(x2 - arrowSize * Math.cos(angle - Math.PI / 6),
                      y2 - arrowSize * Math.sin(angle - Math.PI / 6));
        arrow.lineTo(x2 - arrowSize * Math.cos(angle + Math.PI / 6),
                      y2 - arrowSize * Math.sin(angle + Math.PI / 6));
        arrow.closePath();

        g2.fill(arrow);
    }

    // ── Override para hacer click-through cuando no hay herramienta ──

    @Override
    public boolean contains(int x, int y) {
        // Si no hay herramienta activa, dejar que los clicks pasen al componente debajo
        if (currentTool == Tool.NONE) {
            return false;
        }
        return super.contains(x, y);
    }
}
