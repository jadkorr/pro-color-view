package com.procolorview.editor;

import javax.swing.text.*;

/**
 * StyledEditorKit con word-wrap correcto en macOS y Windows.
 *
 * Claves:
 *   - WrapLabelView: minSpan(X) = 0 → permite que el texto se rompa.
 *   - NoWrapSectionView: en modo wrap, propaga correctamente el ancho
 *     del viewport a los hijos (ParagraphView). En modo no-wrap, deja
 *     que cada párrafo use su ancho natural.
 *   - CustomParagraphView: minSpan(X) = 0 → permite que los párrafos
 *     se compriman al ancho del viewport en modo wrap.
 */
public class WrapEditorKit extends StyledEditorKit {

    private final ViewFactory factory = new WrapColumnFactory();

    @Override
    public ViewFactory getViewFactory() {
        return factory;
    }

    private static class WrapColumnFactory implements ViewFactory {
        @Override
        public View create(Element element) {
            String kind = element.getName();

            if (AbstractDocument.ContentElementName.equals(kind)) {
                return new WrapLabelView(element);
            }
            if (AbstractDocument.ParagraphElementName.equals(kind)) {
                return new WrapParagraphView(element);
            }
            if (AbstractDocument.SectionElementName.equals(kind)) {
                return new WrapSectionView(element, View.Y_AXIS);
            }
            if (StyleConstants.ComponentElementName.equals(kind)) {
                return new ComponentView(element);
            }
            if (StyleConstants.IconElementName.equals(kind)) {
                return new IconView(element);
            }
            return new LabelView(element);
        }
    }

    /**
     * LabelView con minSpan(X) = 0 para permitir word-wrap.
     */
    private static class WrapLabelView extends LabelView {
        public WrapLabelView(Element element) {
            super(element);
        }

        @Override
        public float getMinimumSpan(int axis) {
            if (axis == View.X_AXIS) return 0;
            return super.getMinimumSpan(axis);
        }
    }

    /**
     * ParagraphView con minSpan(X) = 0.
     * Esto es necesario para que en modo wrap los párrafos se compriman
     * al ancho del viewport en vez de mantener su ancho natural.
     */
    private static class WrapParagraphView extends ParagraphView {
        public WrapParagraphView(Element element) {
            super(element);
        }

        @Override
        public float getMinimumSpan(int axis) {
            if (axis == View.X_AXIS) return 0;
            return super.getMinimumSpan(axis);
        }
    }

    /**
     * BoxView para el section element que fuerza relayout cuando
     * cambia el ancho del contenedor. Esto resuelve el bug en Windows
     * donde el layout no se invalida correctamente al resize/toggle wrap.
     */
    private static class WrapSectionView extends BoxView {
        public WrapSectionView(Element element, int axis) {
            super(element, axis);
        }

        /**
         * Forzar re-layout de todos los hijos cuando el ancho cambia.
         * Sin esto, en Windows los ParagraphView mantienen el layout viejo
         * después de toggle wrap, causando selección incorrecta.
         */
        @Override
        protected void layout(int width, int height) {
            // Comparar con el ancho anterior; si cambió, invalidar hijos
            if (width != getWidth()) {
                layoutChanged(View.X_AXIS);
                layoutChanged(View.Y_AXIS);
                for (int i = 0; i < getViewCount(); i++) {
                    View child = getView(i);
                    child.preferenceChanged(this, true, true);
                }
            }
            super.layout(width, height);
        }
    }
}
