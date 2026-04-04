package com.procolorview.theme;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.Theme;

import java.awt.Color;
import java.awt.Font;
import java.awt.GraphicsEnvironment;

/**
 * Tema de colores para Pro Color View.
 * Se adapta al tema actual de Burp Suite (DARK / LIGHT).
 *
 * Uso: ProColorTheme theme = ProColorTheme.fromBurp(api);
 *      Color bg = theme.bg();
 */
public final class ProColorTheme {

    private final boolean dark;

    // ── Fondos y generales ──────────────────────────────────────────
    public final Color bg;
    public final Color fg;
    public final Color selection;
    public final Color caret;
    public final Color searchFieldBg;

    // ── Fuente ──────────────────────────────────────────────────────
    public final Font editorFont;

    // ── HTTP Request line ───────────────────────────────────────────
    public final Color methodColor;
    public final Color urlColor;
    public final Color versionColor;

    // ── HTTP Response status ────────────────────────────────────────
    public final Color status2xx;
    public final Color status3xx;
    public final Color status4xx;
    public final Color status5xx;

    // ── Headers ─────────────────────────────────────────────────────
    public final Color headerName;
    public final Color headerValue;
    public final Color headerMeta;

    // ── Body hint ───────────────────────────────────────────────────
    public final Color bodyHint;

    // ── JSON tokens ─────────────────────────────────────────────────
    public final Color jsonKey;
    public final Color jsonString;
    public final Color jsonNumber;
    public final Color jsonLiteral;
    public final Color jsonBracket;

    // ── XML/HTML tokens ─────────────────────────────────────────────
    public final Color xmlTag;
    public final Color xmlAttrName;
    public final Color xmlAttrValue;
    public final Color xmlContent;
    public final Color xmlComment;

    // ── Form-urlencoded ─────────────────────────────────────────────
    public final Color formKey;
    public final Color formValue;
    public final Color formSeparator;

    // ── Search highlight ────────────────────────────────────────────
    public final Color searchMatch;

    /**
     * Crea el tema leyendo el tema actual de Burp Suite.
     */
    public static ProColorTheme fromBurp(MontoyaApi api) {
        boolean isDark = api.userInterface().currentTheme() == Theme.DARK;
        return new ProColorTheme(isDark);
    }

    /**
     * Crea el tema con un modo explícito.
     */
    public static ProColorTheme of(boolean dark) {
        return new ProColorTheme(dark);
    }

    public boolean isDark() {
        return dark;
    }

    public Color getStatusColor(int statusCode) {
        if (statusCode >= 500) return status5xx;
        if (statusCode >= 400) return status4xx;
        if (statusCode >= 300) return status3xx;
        return status2xx;
    }

    // ── Constructor privado ─────────────────────────────────────────

    private ProColorTheme(boolean dark) {
        this.dark = dark;
        this.editorFont = detectFont();

        if (dark) {
            // ── DARK THEME ──────────────────────────────────────
            bg            = new Color(18, 22, 28);
            fg            = new Color(222, 226, 230);
            selection     = new Color(52, 65, 85);
            caret         = new Color(124, 211, 255);
            searchFieldBg = new Color(25, 30, 38);

            methodColor   = new Color(255, 166, 87);    // naranja
            urlColor      = new Color(124, 211, 255);   // cyan
            versionColor  = new Color(167, 139, 250);   // violeta

            status2xx     = new Color(94, 234, 212);    // verde/teal
            status3xx     = new Color(124, 211, 255);   // cyan
            status4xx     = new Color(255, 166, 87);    // naranja
            status5xx     = new Color(248, 113, 113);   // rojo

            headerName    = new Color(250, 204, 21);    // amarillo
            headerValue   = new Color(201, 209, 217);   // gris claro
            headerMeta    = new Color(244, 114, 182);   // rosa

            bodyHint      = new Color(163, 172, 183);

            jsonKey       = new Color(124, 211, 255);   // cyan
            jsonString    = new Color(134, 239, 172);   // verde
            jsonNumber    = new Color(255, 166, 87);    // naranja
            jsonLiteral   = new Color(196, 181, 253);   // lavanda
            jsonBracket   = new Color(201, 209, 217);   // gris

            xmlTag        = new Color(248, 113, 113);   // rojo
            xmlAttrName   = new Color(255, 166, 87);    // naranja
            xmlAttrValue  = new Color(134, 239, 172);   // verde
            xmlContent    = new Color(201, 209, 217);   // gris claro
            xmlComment    = new Color(110, 120, 136);   // gris oscuro

            formKey       = new Color(124, 211, 255);
            formValue     = new Color(134, 239, 172);
            formSeparator = new Color(163, 172, 183);

            searchMatch   = new Color(255, 214, 102, 80);
        } else {
            // ── LIGHT THEME ─────────────────────────────────────
            bg            = new Color(255, 255, 255);
            fg            = new Color(36, 41, 47);
            selection     = new Color(173, 214, 255);
            caret         = new Color(0, 100, 200);
            searchFieldBg = new Color(240, 242, 245);

            methodColor   = new Color(207, 87, 0);      // naranja oscuro
            urlColor      = new Color(0, 105, 170);     // azul
            versionColor  = new Color(110, 80, 190);    // violeta

            status2xx     = new Color(22, 128, 96);     // verde oscuro
            status3xx     = new Color(0, 105, 170);     // azul
            status4xx     = new Color(207, 87, 0);      // naranja
            status5xx     = new Color(207, 34, 46);     // rojo

            headerName    = new Color(150, 115, 0);     // amarillo oscuro
            headerValue   = new Color(36, 41, 47);      // negro/gris oscuro
            headerMeta    = new Color(191, 57, 137);    // rosa oscuro

            bodyHint      = new Color(87, 96, 106);

            jsonKey       = new Color(0, 105, 170);     // azul
            jsonString    = new Color(17, 99, 41);      // verde oscuro
            jsonNumber    = new Color(207, 87, 0);      // naranja
            jsonLiteral   = new Color(110, 80, 190);    // violeta
            jsonBracket   = new Color(87, 96, 106);     // gris

            xmlTag        = new Color(207, 34, 46);     // rojo
            xmlAttrName   = new Color(207, 87, 0);      // naranja
            xmlAttrValue  = new Color(17, 99, 41);      // verde oscuro
            xmlContent    = new Color(36, 41, 47);      // negro
            xmlComment    = new Color(140, 149, 159);   // gris

            formKey       = new Color(0, 105, 170);
            formValue     = new Color(17, 99, 41);
            formSeparator = new Color(87, 96, 106);

            searchMatch   = new Color(255, 214, 102, 100);
        }
    }

    private static Font detectFont() {
        String[] available = GraphicsEnvironment
                .getLocalGraphicsEnvironment().getAvailableFontFamilyNames();
        for (String f : available) {
            if (f.equals("JetBrains Mono")) return new Font("JetBrains Mono", Font.PLAIN, 12);
        }
        for (String f : available) {
            if (f.equals("Menlo")) return new Font("Menlo", Font.PLAIN, 12);
        }
        return new Font(Font.MONOSPACED, Font.PLAIN, 12);
    }
}
