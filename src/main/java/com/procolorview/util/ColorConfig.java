package com.procolorview.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import javax.swing.*;
import java.awt.*;

/**
 * Configurable colors for parameter colorization in Pro Color View.
 *
 * Persisted in the Burp project via extensionData() so they survive
 * extension reloads and project re-opens.
 *
 * Default colors match JSON theme (key=cyan/blue, value=green, etc.)
 * Users can customize and reset to defaults at any time.
 */
public class ColorConfig {

    private static final String PREFIX = "pcv_color_";

    private static MontoyaApi burpApi;

    // ── Immutable defaults (same as JSON colors) ───────────────────
    // Dark
    private static final Color DEF_KEY_DARK   = new Color(124, 211, 255);  // cyan (jsonKey)
    private static final Color DEF_EQUAL_DARK = new Color(201, 209, 217);  // gris claro (jsonBracket)
    private static final Color DEF_VALUE_DARK = new Color(134, 239, 172);  // verde (jsonString)
    private static final Color DEF_SEP_DARK   = new Color(163, 172, 183);  // gris
    // Light
    private static final Color DEF_KEY_LIGHT   = new Color(0, 105, 170);   // azul (jsonKey)
    private static final Color DEF_EQUAL_LIGHT = new Color(87, 96, 106);   // gris (jsonBracket)
    private static final Color DEF_VALUE_LIGHT = new Color(17, 99, 41);    // verde oscuro (jsonString)
    private static final Color DEF_SEP_LIGHT   = new Color(140, 149, 159); // gris

    // ── Current (mutable) colors ───────────────────────────────────
    private static Color paramKeyDark   = DEF_KEY_DARK;
    private static Color paramEqualDark = DEF_EQUAL_DARK;
    private static Color paramValueDark = DEF_VALUE_DARK;
    private static Color paramSepDark   = DEF_SEP_DARK;

    private static Color paramKeyLight   = DEF_KEY_LIGHT;
    private static Color paramEqualLight = DEF_EQUAL_LIGHT;
    private static Color paramValueLight = DEF_VALUE_LIGHT;
    private static Color paramSepLight   = DEF_SEP_LIGHT;

    // ── Initialization ─────────────────────────────────────────────

    public static void init(MontoyaApi api) {
        burpApi = api;
        loadFromProject();
    }

    // ── Getters ────────────────────────────────────────────────────

    public static Color paramKey(boolean dark)   { return dark ? paramKeyDark   : paramKeyLight; }
    public static Color paramEqual(boolean dark)  { return dark ? paramEqualDark : paramEqualLight; }
    public static Color paramValue(boolean dark)  { return dark ? paramValueDark : paramValueLight; }
    public static Color paramSep(boolean dark)    { return dark ? paramSepDark   : paramSepLight; }

    // ── Reset to defaults ──────────────────────────────────────────

    public static void resetToDefaults() {
        paramKeyDark   = DEF_KEY_DARK;
        paramEqualDark = DEF_EQUAL_DARK;
        paramValueDark = DEF_VALUE_DARK;
        paramSepDark   = DEF_SEP_DARK;
        paramKeyLight   = DEF_KEY_LIGHT;
        paramEqualLight = DEF_EQUAL_LIGHT;
        paramValueLight = DEF_VALUE_LIGHT;
        paramSepLight   = DEF_SEP_LIGHT;
        clearFromProject();
    }

    // ── Persistence ────────────────────────────────────────────────

    private static void loadFromProject() {
        if (burpApi == null) return;
        try {
            PersistedObject data = burpApi.persistence().extensionData();
            paramKeyDark   = loadColor(data, "paramKey_dark",   paramKeyDark);
            paramEqualDark = loadColor(data, "paramEqual_dark", paramEqualDark);
            paramValueDark = loadColor(data, "paramValue_dark", paramValueDark);
            paramSepDark   = loadColor(data, "paramSep_dark",   paramSepDark);
            paramKeyLight   = loadColor(data, "paramKey_light",   paramKeyLight);
            paramEqualLight = loadColor(data, "paramEqual_light", paramEqualLight);
            paramValueLight = loadColor(data, "paramValue_light", paramValueLight);
            paramSepLight   = loadColor(data, "paramSep_light",   paramSepLight);
        } catch (Exception ignored) {}
    }

    private static void saveToProject() {
        if (burpApi == null) return;
        try {
            PersistedObject data = burpApi.persistence().extensionData();
            saveColor(data, "paramKey_dark",   paramKeyDark);
            saveColor(data, "paramEqual_dark", paramEqualDark);
            saveColor(data, "paramValue_dark", paramValueDark);
            saveColor(data, "paramSep_dark",   paramSepDark);
            saveColor(data, "paramKey_light",   paramKeyLight);
            saveColor(data, "paramEqual_light", paramEqualLight);
            saveColor(data, "paramValue_light", paramValueLight);
            saveColor(data, "paramSep_light",   paramSepLight);
        } catch (Exception ignored) {}
    }

    /** Remove all persisted color keys so next load uses defaults */
    private static void clearFromProject() {
        if (burpApi == null) return;
        try {
            PersistedObject data = burpApi.persistence().extensionData();
            String[] keys = {"paramKey_dark", "paramEqual_dark", "paramValue_dark", "paramSep_dark",
                    "paramKey_light", "paramEqual_light", "paramValue_light", "paramSep_light"};
            for (String key : keys) {
                data.deleteString(PREFIX + key);
            }
        } catch (Exception ignored) {}
    }

    private static Color loadColor(PersistedObject data, String key, Color fallback) {
        String val = data.getString(PREFIX + key);
        if (val != null && !val.isEmpty()) {
            try {
                return new Color(Integer.parseInt(val, 16), true);
            } catch (NumberFormatException ignored) {}
        }
        return fallback;
    }

    private static void saveColor(PersistedObject data, String key, Color color) {
        data.setString(PREFIX + key, String.format("%08X", color.getRGB()));
    }

    // ── Config Dialog ──────────────────────────────────────────────

    /**
     * Opens a dialog to configure parameter colors.
     * Returns true if user clicked OK (colors changed).
     */
    public static boolean showConfigDialog(Component parent, boolean isDark) {
        Color[] defaults = isDark
                ? new Color[]{DEF_KEY_DARK, DEF_EQUAL_DARK, DEF_VALUE_DARK, DEF_SEP_DARK}
                : new Color[]{DEF_KEY_LIGHT, DEF_EQUAL_LIGHT, DEF_VALUE_LIGHT, DEF_SEP_LIGHT};
        Color[] colors = isDark
                ? new Color[]{paramKeyDark, paramEqualDark, paramValueDark, paramSepDark}
                : new Color[]{paramKeyLight, paramEqualLight, paramValueLight, paramSepLight};
        String[] labels = {"Parameter (key)", "Equal sign (=)", "Value", "Separator (&, ?)"};

        JPanel panel = new JPanel(new GridLayout(labels.length, 3, 8, 6));

        JButton[] colorBtns = new JButton[labels.length];
        JLabel[] previews = new JLabel[labels.length];

        for (int i = 0; i < labels.length; i++) {
            final int idx = i;
            JLabel lbl = new JLabel(labels[i]);
            lbl.setFont(new Font(Font.MONOSPACED, Font.BOLD, 12));

            JButton btn = new JButton();
            btn.setPreferredSize(new Dimension(60, 24));
            btn.setBackground(colors[i]);
            btn.setOpaque(true);
            btn.setBorderPainted(true);
            btn.setToolTipText("Click to change color");
            colorBtns[i] = btn;

            JLabel preview = new JLabel("  \u2588\u2588\u2588 sample");
            preview.setForeground(colors[i]);
            preview.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            previews[i] = preview;

            btn.addActionListener(e -> {
                Color picked = JColorChooser.showDialog(parent, "Choose color for " + labels[idx], colors[idx]);
                if (picked != null) {
                    colors[idx] = picked;
                    btn.setBackground(picked);
                    preview.setForeground(picked);
                }
            });

            panel.add(lbl);
            panel.add(btn);
            panel.add(preview);
        }

        // Reset button
        JButton resetBtn = new JButton("Reset to Defaults");
        resetBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        resetBtn.setForeground(new Color(248, 113, 113));
        resetBtn.addActionListener(e -> {
            for (int i = 0; i < colors.length; i++) {
                colors[i] = defaults[i];
                colorBtns[i].setBackground(defaults[i]);
                previews[i].setForeground(defaults[i]);
            }
        });

        JPanel bottomPanel = new JPanel(new BorderLayout());
        JLabel hint = new JLabel("Colors are saved per project and persist across reloads.");
        hint.setFont(hint.getFont().deriveFont(Font.ITALIC, 10f));
        bottomPanel.add(hint, BorderLayout.CENTER);
        bottomPanel.add(resetBtn, BorderLayout.EAST);

        JPanel wrapper = new JPanel(new BorderLayout(0, 8));
        String themeLabel = isDark ? "Dark Theme" : "Light Theme";
        JLabel header = new JLabel("Configure Parameter Colors (" + themeLabel + ")");
        header.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        wrapper.add(header, BorderLayout.NORTH);
        wrapper.add(panel, BorderLayout.CENTER);
        wrapper.add(bottomPanel, BorderLayout.SOUTH);

        int result = JOptionPane.showConfirmDialog(parent, wrapper,
                "Pro Color View \u2014 Parameter Colors", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return false;

        // Check if reset to defaults
        boolean isDefault = true;
        for (int i = 0; i < colors.length; i++) {
            if (!colors[i].equals(defaults[i])) { isDefault = false; break; }
        }

        if (isDark) {
            paramKeyDark   = colors[0];
            paramEqualDark = colors[1];
            paramValueDark = colors[2];
            paramSepDark   = colors[3];
        } else {
            paramKeyLight   = colors[0];
            paramEqualLight = colors[1];
            paramValueLight = colors[2];
            paramSepLight   = colors[3];
        }

        if (isDefault) {
            // If all colors are defaults, clear persisted data
            clearFromProject();
        } else {
            saveToProject();
        }
        return true;
    }
}
