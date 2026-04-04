package com.procolorview.editor;

import java.awt.*;

/**
 * FlowLayout subclass that wraps components to the next line
 * when there isn't enough horizontal space, and reports the
 * correct preferred size so parent containers can resize.
 */
public class WrapLayout extends FlowLayout {

    public WrapLayout() {
        super(FlowLayout.LEFT, 2, 1);
    }

    public WrapLayout(int align, int hgap, int vgap) {
        super(align, hgap, vgap);
    }

    @Override
    public Dimension preferredLayoutSize(Container target) {
        return computeSize(target, true);
    }

    @Override
    public Dimension minimumLayoutSize(Container target) {
        Dimension d = computeSize(target, false);
        d.width = 0; // allow shrinking fully
        return d;
    }

    private Dimension computeSize(Container target, boolean preferred) {
        synchronized (target.getTreeLock()) {
            int maxWidth = getTargetWidth(target);
            if (maxWidth <= 0) maxWidth = Integer.MAX_VALUE;

            Insets insets = target.getInsets();
            int hgap = getHgap();
            int vgap = getVgap();

            int x = insets.left + hgap;
            int y = insets.top + vgap;
            int rowH = 0;

            for (int i = 0; i < target.getComponentCount(); i++) {
                Component c = target.getComponent(i);
                if (!c.isVisible()) continue;
                Dimension d = preferred ? c.getPreferredSize() : c.getMinimumSize();
                if (x + d.width + hgap > maxWidth && x > insets.left + hgap) {
                    // Wrap to next line
                    x = insets.left + hgap;
                    y += rowH + vgap;
                    rowH = 0;
                }
                x += d.width + hgap;
                rowH = Math.max(rowH, d.height);
            }
            y += rowH + vgap;
            return new Dimension(maxWidth, y + insets.bottom);
        }
    }

    private int getTargetWidth(Container target) {
        Container parent = target.getParent();
        if (parent != null && parent.getWidth() > 0) {
            Insets pi = parent.getInsets();
            return parent.getWidth() - pi.left - pi.right;
        }
        return target.getWidth();
    }
}
