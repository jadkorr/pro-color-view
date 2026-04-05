package com.procolorview.colorizer;

import com.procolorview.theme.ProColorTheme;

import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyledDocument;
import java.awt.Color;
import java.util.Set;

import static com.procolorview.colorizer.HttpColorizer.append;
import static com.procolorview.colorizer.HttpColorizer.style;

/**
 * Colorizes JavaScript source code within a StyledDocument.
 *
 * Uses a linear character scanner (NOT regex) for reliability on
 * large minified JS bundles. Handles:
 *   - Keywords → bold purple
 *   - Strings (single/double/backtick) → green
 *   - Numbers → orange
 *   - Comments (// and /* ... * /) → gray
 *   - Known globals (document, window, fetch...) → blue
 *   - Operators/punctuation → bracket color
 *
 * For very large JS (>500KB), falls back to plain text to avoid
 * StyledDocument performance issues.
 */
public final class JsColorizer {

    private JsColorizer() {}

    private static final int MAX_COLORIZE_LENGTH = 200_000; // 200KB limit for full colorization
    private static final int BATCH_SIZE = 512; // Flush buffer every N chars to reduce insertString calls

    private static final Set<String> KEYWORDS = Set.of(
            "abstract", "arguments", "async", "await", "break", "case", "catch",
            "class", "const", "continue", "debugger", "default", "delete", "do",
            "else", "enum", "export", "extends", "false", "finally", "for",
            "function", "if", "implements", "import", "in", "instanceof", "interface",
            "let", "new", "null", "of", "package", "private", "protected", "public",
            "return", "static", "super", "switch", "this", "throw", "true", "try",
            "typeof", "undefined", "var", "void", "while", "with", "yield"
    );

    private static final Set<String> GLOBALS = Set.of(
            "document", "window", "console", "fetch", "XMLHttpRequest", "JSON",
            "Math", "Array", "Object", "String", "Number", "Boolean", "Promise",
            "setTimeout", "setInterval", "clearTimeout", "clearInterval",
            "alert", "confirm", "prompt", "localStorage", "sessionStorage",
            "navigator", "location", "history", "performance", "crypto",
            "addEventListener", "removeEventListener", "querySelector",
            "querySelectorAll", "getElementById", "createElement",
            "require", "module", "exports", "process", "Buffer",
            "eval", "encodeURIComponent", "decodeURIComponent", "atob", "btoa",
            "Error", "TypeError", "RangeError", "SyntaxError", "RegExp",
            "Map", "Set", "WeakMap", "WeakSet", "Symbol", "Proxy", "Reflect",
            "Intl", "Date", "Function", "Uint8Array", "ArrayBuffer", "DataView"
    );

    private static final String OPERATORS = "{}()[];,.=><!&|?:+-*/%^~";

    public static void colorize(StyledDocument doc, String js, ProColorTheme theme) throws Exception {
        // Very large JS (>1MB): plain text, no colorization
        if (js.length() > 1_000_000) {
            append(doc, js, style(theme.fg, false));
            return;
        }
        // Large JS (200KB-1MB): partial colorization (strings, comments, keywords only)
        if (js.length() > MAX_COLORIZE_LENGTH) {
            colorizePartial(doc, js, theme);
            return;
        }

        boolean isDark = theme.isDark();

        SimpleAttributeSet keywordStyle  = style(isDark ? new Color(198, 120, 221) : new Color(152, 50, 170), true);
        SimpleAttributeSet stringStyle   = style(theme.jsonString, false);
        SimpleAttributeSet numberStyle   = style(theme.jsonNumber, false);
        SimpleAttributeSet commentStyle  = style(isDark ? new Color(106, 115, 125) : new Color(140, 140, 140), false);
        SimpleAttributeSet globalStyle   = style(isDark ? new Color(97, 175, 239)  : new Color(0, 100, 180), false);
        SimpleAttributeSet operStyle     = style(theme.jsonBracket, false);
        SimpleAttributeSet defaultStyle  = style(theme.fg, false);
        SimpleAttributeSet templateStyle = style(isDark ? new Color(152, 195, 121) : new Color(50, 130, 50), false);

        int len = js.length();
        int i = 0;
        StringBuilder buf = new StringBuilder(); // accumulator for default text

        while (i < len) {
            char c = js.charAt(i);

            // ── Single-line comment: // ──
            if (c == '/' && i + 1 < len && js.charAt(i + 1) == '/') {
                flushBuf(doc, buf, defaultStyle);
                int end = js.indexOf('\n', i);
                if (end < 0) end = len;
                append(doc, js.substring(i, end), commentStyle);
                i = end;
                continue;
            }

            // ── Multi-line comment: /* ... */ ──
            if (c == '/' && i + 1 < len && js.charAt(i + 1) == '*') {
                flushBuf(doc, buf, defaultStyle);
                int end = js.indexOf("*/", i + 2);
                if (end < 0) end = len - 2; // unclosed: take all
                end += 2; // include */
                append(doc, js.substring(i, Math.min(end, len)), commentStyle);
                i = Math.min(end, len);
                continue;
            }

            // ── Double-quoted string ──
            if (c == '"') {
                flushBuf(doc, buf, defaultStyle);
                int end = scanString(js, i, '"');
                append(doc, js.substring(i, end), stringStyle);
                i = end;
                continue;
            }

            // ── Single-quoted string ──
            if (c == '\'') {
                flushBuf(doc, buf, defaultStyle);
                int end = scanString(js, i, '\'');
                append(doc, js.substring(i, end), stringStyle);
                i = end;
                continue;
            }

            // ── Template literal (backtick) ──
            if (c == '`') {
                flushBuf(doc, buf, defaultStyle);
                int end = scanString(js, i, '`');
                append(doc, js.substring(i, end), templateStyle);
                i = end;
                continue;
            }

            // ── Number ──
            if (isDigitStart(c, js, i)) {
                flushBuf(doc, buf, defaultStyle);
                int end = scanNumber(js, i);
                append(doc, js.substring(i, end), numberStyle);
                i = end;
                continue;
            }

            // ── Word (identifier / keyword / global) ──
            if (isIdentStart(c)) {
                flushBuf(doc, buf, defaultStyle);
                int end = i + 1;
                while (end < len && isIdentPart(js.charAt(end))) end++;
                String word = js.substring(i, end);
                if (KEYWORDS.contains(word)) {
                    append(doc, word, keywordStyle);
                } else if (GLOBALS.contains(word)) {
                    append(doc, word, globalStyle);
                } else {
                    append(doc, word, defaultStyle);
                }
                i = end;
                continue;
            }

            // ── Operator / punctuation ──
            if (OPERATORS.indexOf(c) >= 0) {
                flushBuf(doc, buf, defaultStyle);
                append(doc, String.valueOf(c), operStyle);
                i++;
                continue;
            }

            // ── Default (whitespace, other chars) ──
            buf.append(c);
            i++;
        }

        // Flush remaining buffer
        flushBuf(doc, buf, defaultStyle);
    }

    // ── Scanner helpers ──────────────────────────────────────────────

    /** Scan a quoted string starting at pos (the quote char). Returns end index (exclusive). */
    private static int scanString(String s, int pos, char quote) {
        int len = s.length();
        int i = pos + 1; // skip opening quote
        while (i < len) {
            char c = s.charAt(i);
            if (c == '\\') {
                i += 2; // skip escaped char
                continue;
            }
            if (c == quote) {
                return i + 1; // include closing quote
            }
            // For non-backtick strings, newline ends the string (unterminated)
            if (quote != '`' && c == '\n') {
                return i;
            }
            i++;
        }
        return len; // unterminated string — take to end
    }

    /** Check if this position starts a number literal */
    private static boolean isDigitStart(char c, String s, int pos) {
        if (c >= '0' && c <= '9') return true;
        // .5 style decimal
        if (c == '.' && pos + 1 < s.length()) {
            char next = s.charAt(pos + 1);
            return next >= '0' && next <= '9';
        }
        return false;
    }

    /** Scan a number literal. Returns end index (exclusive). */
    private static int scanNumber(String s, int pos) {
        int len = s.length();
        int i = pos;
        // Hex: 0x, Octal: 0o, Binary: 0b
        if (i + 1 < len && s.charAt(i) == '0') {
            char next = s.charAt(i + 1);
            if (next == 'x' || next == 'X') { i += 2; while (i < len && isHex(s.charAt(i))) i++; return i; }
            if (next == 'o' || next == 'O') { i += 2; while (i < len && s.charAt(i) >= '0' && s.charAt(i) <= '7') i++; return i; }
            if (next == 'b' || next == 'B') { i += 2; while (i < len && (s.charAt(i) == '0' || s.charAt(i) == '1')) i++; return i; }
        }
        // Decimal / float
        while (i < len && (s.charAt(i) >= '0' && s.charAt(i) <= '9')) i++;
        if (i < len && s.charAt(i) == '.') {
            i++;
            while (i < len && (s.charAt(i) >= '0' && s.charAt(i) <= '9')) i++;
        }
        // Exponent
        if (i < len && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
            i++;
            if (i < len && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
            while (i < len && (s.charAt(i) >= '0' && s.charAt(i) <= '9')) i++;
        }
        // BigInt suffix
        if (i < len && s.charAt(i) == 'n') i++;
        return i;
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean isIdentStart(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$';
    }

    private static boolean isIdentPart(char c) {
        return isIdentStart(c) || (c >= '0' && c <= '9');
    }

    /** Flush the accumulated buffer as default text */
    private static void flushBuf(StyledDocument doc, StringBuilder buf, SimpleAttributeSet style) throws Exception {
        if (buf.length() > 0) {
            append(doc, buf.toString(), style);
            buf.setLength(0);
        }
    }

    /**
     * Fast partial colorization for large JS (between MAX_COLORIZE_LENGTH and 1MB).
     * Only colorizes strings, comments, and keywords — skips fine-grained token analysis.
     */
    private static void colorizePartial(StyledDocument doc, String js, ProColorTheme theme) throws Exception {
        boolean isDark = theme.isDark();
        SimpleAttributeSet keywordStyle = style(isDark ? new Color(198, 120, 221) : new Color(152, 50, 170), true);
        SimpleAttributeSet stringStyle  = style(theme.jsonString, false);
        SimpleAttributeSet commentStyle = style(isDark ? new Color(106, 115, 125) : new Color(140, 140, 140), false);
        SimpleAttributeSet defaultStyle = style(theme.fg, false);

        int len = js.length();
        int i = 0;
        StringBuilder buf = new StringBuilder(BATCH_SIZE * 2);

        while (i < len) {
            char c = js.charAt(i);

            // Comments
            if (c == '/' && i + 1 < len) {
                char n = js.charAt(i + 1);
                if (n == '/') {
                    flushBuf(doc, buf, defaultStyle);
                    int end = js.indexOf('\n', i);
                    if (end < 0) end = len;
                    append(doc, js.substring(i, end), commentStyle);
                    i = end; continue;
                }
                if (n == '*') {
                    flushBuf(doc, buf, defaultStyle);
                    int end = js.indexOf("*/", i + 2);
                    end = (end < 0) ? len : end + 2;
                    append(doc, js.substring(i, Math.min(end, len)), commentStyle);
                    i = Math.min(end, len); continue;
                }
            }

            // Strings
            if (c == '"' || c == '\'' || c == '`') {
                flushBuf(doc, buf, defaultStyle);
                int end = scanString(js, i, c);
                append(doc, js.substring(i, end), stringStyle);
                i = end; continue;
            }

            // Keywords (quick check)
            if (isIdentStart(c)) {
                int end = i + 1;
                while (end < len && isIdentPart(js.charAt(end))) end++;
                String word = js.substring(i, end);
                if (KEYWORDS.contains(word)) {
                    flushBuf(doc, buf, defaultStyle);
                    append(doc, word, keywordStyle);
                } else {
                    buf.append(word);
                }
                i = end; continue;
            }

            buf.append(c);
            if (buf.length() >= BATCH_SIZE) {
                flushBuf(doc, buf, defaultStyle);
            }
            i++;
        }
        flushBuf(doc, buf, defaultStyle);
    }
}
