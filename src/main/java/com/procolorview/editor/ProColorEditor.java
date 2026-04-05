package com.procolorview.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.procolorview.ai.AiPanel;
import com.procolorview.colorizer.HttpColorizer;
import com.procolorview.overlay.OverlayManager;
import com.procolorview.parser.HttpMessageParser;
import com.procolorview.parser.ParsedHttpMessage;
import com.procolorview.search.SearchManager;
import com.procolorview.theme.ProColorTheme;
import com.procolorview.util.CurlExporter;
import com.procolorview.util.Decoder;
import com.procolorview.util.EditorHistory;
import com.procolorview.util.JwtDecoder;
import com.procolorview.util.LinkFinder;
import com.procolorview.util.SecretsFinder;
import com.procolorview.util.TemplateVars;

import javax.swing.*;
import javax.swing.event.CaretEvent;
import javax.swing.event.CaretListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultCaret;
import javax.swing.text.Document;
import javax.swing.undo.UndoManager;
import javax.swing.undo.CannotRedoException;
import javax.swing.undo.CannotUndoException;
import java.awt.*;
import java.awt.FlowLayout;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.FileWriter;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Pro Color View Editor v3.2
 *
 * Decoder panel BIDIRECCIONAL:
 *   - Seleccionas texto codificado → aparece decodificado abajo (editable)
 *   - Editas el texto decodificado → se re-codifica automáticamente en el editor
 *   - Combo box para elegir el tipo de encoding (Base64, URL, Hex, HTML, Unicode)
 *   - JWT se muestra pero no es re-encodeable (requiere firma)
 */
public class ProColorEditor {

    private final MontoyaApi api;
    private final JPanel mainPanel;
    private final WrapTextPane editor;
    private JScrollPane scrollPane;
    private final SearchManager searchManager;
    private final ProColorTheme theme;
    private final UndoManager undoManager;

    // Toolbar
    private JTextField searchField;
    private JTextField replaceField;
    private JTextField highlightField;
    private JTextField blurField;
    private JCheckBox wrapCheckbox;
    private JCheckBox linesCheckbox;
    private JButton prettyBtn;
    private JLabel searchStatus;

    // Line numbers
    private LineNumberGutter lineGutter;

    // Decoder panel (bidirectional: decode ↔ encode)
    private JPanel decoderPanel;
    private JComboBox<String> decoderCombo;
    private JTextArea decoderText;
    private JButton decoderCopyBtn;
    private int decoderSelStart = -1;      // posición inicio en editor
    private int decoderSelEnd   = -1;      // posición fin en editor
    private boolean decoderBusy = false;   // previene recursión
    private boolean isDecodeMode = true;   // true=decode, false=encode
    private Map<String, String> currentResults = new LinkedHashMap<>();

    // Status bar
    private JLabel statsLabel;

    // Editor history (versioning)
    private final EditorHistory editorHistory = new EditorHistory();

    // State
    private byte[] currentContent;
    private boolean isRequest;
    private boolean modified = false;
    private boolean updating = false;
    private boolean prettyMode = true;
    private ParsedHttpMessage lastParsed;
    private int lastContentHash = 0; // hash of last rendered content to skip re-render

    // LRU cache: content hash → rendered StyledDocument (avoids re-colorizing same content)
    private static final int DOC_CACHE_SIZE = 10;
    private final LinkedHashMap<Integer, javax.swing.text.DefaultStyledDocument> docCache =
            new LinkedHashMap<Integer, javax.swing.text.DefaultStyledDocument>(DOC_CACHE_SIZE + 1, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<Integer, javax.swing.text.DefaultStyledDocument> eldest) {
                    return size() > DOC_CACHE_SIZE;
                }
            };

    // Async render: track current worker so we can cancel if user navigates away
    private SwingWorker<javax.swing.text.DefaultStyledDocument, Void> asyncRenderWorker;

    // Original HttpService from Burp (for correct host/port/https when sending)
    private HttpService originalService;

    // Minimize Headers state: stores ALL original headers so hidden ones can be restored
    private List<Map.Entry<String, String>> originalHeaders;
    private String originalStartLine;
    private String originalBody;
    private Set<String> hiddenHeaderKeys; // lowercase header names currently hidden

    // Companion (the other side: if this is request editor, companion = response)
    private byte[] companionContent;
    private boolean companionIsRequest;
    private ParsedHttpMessage companionParsed;

    // Minimize Headers state for companion
    private List<Map.Entry<String, String>> companionOriginalHeaders;
    private String companionOriginalStartLine;
    private String companionOriginalBody;
    private Set<String> companionHiddenHeaderKeys;

    // Plataforma
    private static final boolean IS_MAC = System.getProperty("os.name", "")
            .toLowerCase().contains("mac");
    private static final int MOD = IS_MAC
            ? InputEvent.META_DOWN_MASK : InputEvent.CTRL_DOWN_MASK;

    // Pre-compiled patterns (avoid recompilation in hot paths)
    private static final Pattern PAT_XML_TAG = Pattern.compile("<(\\w+)>([^<]*)</\\1>");
    private static final Pattern PAT_MULTIPART_DISP = Pattern.compile(
            "Content-Disposition:\\s*form-data;\\s*name=\"([^\"]+)\"");
    private static final Pattern PAT_HTML_COMMENT = Pattern.compile("<!--([\\s\\S]*?)-->");
    private static final Pattern PAT_JS_SINGLE_COMMENT = Pattern.compile("//[^\n]+");
    private static final Pattern PAT_JS_BLOCK_COMMENT = Pattern.compile("/\\*([\\s\\S]*?)\\*/");
    private static final Pattern PAT_SCRIPT_SRC = Pattern.compile(
            "(?i)<script[^>]+src\\s*=\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern PAT_SCRIPT_INLINE = Pattern.compile(
            "(?i)<script[^>]*>([\\s\\S]*?)</script>");
    private static final Pattern PAT_FORM_TAG = Pattern.compile(
            "(?i)<form([^>]*)>([\\s\\S]*?)</form>");
    private static final Pattern PAT_ATTR = Pattern.compile(
            "(?i)(action|method|enctype|id|class|name)\\s*=\\s*['\"]([^'\"]*)['\"]");
    private static final Pattern PAT_INPUT_TAG = Pattern.compile(
            "(?i)<(?:input|select|textarea|button)([^>]*)>");
    private static final Pattern PAT_JS_FILE_REF = Pattern.compile(
            "(?i)(?:src|href)\\s*=\\s*['\"]([^'\"]*\\.js(?:\\?[^'\"]*)?)['\"]");

    // AI Panel
    private AiPanel aiPanel;

    // Reusable timer for button feedback
    private javax.swing.Timer feedbackTimer;

    // Reusable document listener (single instance — avoids duplication on doc swap)
    private final DocumentListener docModListener = new DocumentListener() {
        @Override public void insertUpdate(DocumentEvent e)  { markModified(); updateStats(); }
        @Override public void removeUpdate(DocumentEvent e)  { markModified(); updateStats(); }
        @Override public void changedUpdate(DocumentEvent e) { markModified(); }
    };

    public ProColorEditor(MontoyaApi api, ProColorTheme theme) {
        this.api = api;
        this.theme = theme;
        this.undoManager = new UndoManager();
        this.undoManager.setLimit(50);

        mainPanel = new JPanel(new BorderLayout());

        editor = createEditor();
        scrollPane = createScrollPane(true);
        searchManager = new SearchManager(editor);

        lineGutter = new LineNumberGutter(editor, theme.editorFont, theme.bodyHint, theme.bg);
        scrollPane.setRowHeaderView(lineGutter);

        JPanel toolbar = createToolbar();
        decoderPanel = createDecoderPanel();
        JPanel statusBar = createStatusBar();

        aiPanel = new AiPanel(theme, api);
        aiPanel.setContentSuppliers(
                () -> editorText(),
                () -> companionParsed != null ? companionParsed.rebuild() : "",
                () -> {
                    // Raw request bytes: if this is a request editor, use currentContent;
                    // if response editor, use companion content (which is the request)
                    if (isRequest && currentContent != null) return currentContent;
                    if (!isRequest && companionContent != null) return companionContent;
                    return currentContent;
                },
                () -> originalService
        );

        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new BoxLayout(bottomPanel, BoxLayout.Y_AXIS));
        bottomPanel.add(decoderPanel);
        bottomPanel.add(aiPanel);
        bottomPanel.add(statusBar);

        mainPanel.add(toolbar, BorderLayout.NORTH);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        editor.getDocument().addUndoableEditListener(undoManager);
        editor.getDocument().addDocumentListener(docModListener);

        // Decoder + stats: se actualiza al seleccionar texto
        editor.addCaretListener(new CaretListener() {
            @Override public void caretUpdate(CaretEvent e) {
                if (!decoderBusy && !decoderText.hasFocus()) {
                    SwingUtilities.invokeLater(() -> updateDecoderPanel());
                }
                // Update stats to show selection char count
                updateStats();
            }
        });

        bindShortcuts(mainPanel);
        bindEditorShortcuts();
    }

    // ── API pública ─────────────────────────────────────────────────

    public Component getComponent() { return mainPanel; }

    /** Store the original HttpService from Burp so we can reuse it for Send to Intruder/Repeater. */
    public void setOriginalService(HttpService service) {
        this.originalService = service;
    }

    public void setContent(byte[] content, boolean isRequest) {
        this.currentContent = content;
        this.isRequest = isRequest;
        this.updating = true;
        // Reset minimize state on new content
        this.originalHeaders = null;
        this.originalStartLine = null;
        this.originalBody = null;
        this.hiddenHeaderKeys = null;
        try {
            undoManager.discardAllEdits();
            searchManager.clearMatchHighlights();
            if (content == null || content.length == 0) {
                editor.setText("");
                modified = false;
                searchStatus.setText(" ");
                lastParsed = null;
                lastContentHash = 0;
                updateStats();
                return;
            }

            // Cancel any pending async render from a previous item
            if (asyncRenderWorker != null && !asyncRenderWorker.isDone()) {
                asyncRenderWorker.cancel(true);
                asyncRenderWorker = null;
            }

            // Compute hash: content + prettyMode to detect same content
            int contentHash = Arrays.hashCode(content) * 31 + (prettyMode ? 1 : 0) + (isRequest ? 2 : 0);

            // For large binary content (PDF, images, EXE), only convert headers + first 128 bytes
            // instead of converting the entire multi-MB byte[] to String
            boolean isBinary = quickBinaryCheck(content);
            String raw;
            int realBodySize = -1;
            if (isBinary) {
                raw = buildTruncatedRaw(content);
                // Calculate real body size from the original byte[]
                String probe = new String(content, 0, Math.min(content.length, 4096), StandardCharsets.ISO_8859_1);
                int sep = probe.indexOf("\r\n\r\n");
                int bodyStart = (sep >= 0) ? sep + 4 : -1;
                if (bodyStart < 0) { sep = probe.indexOf("\n\n"); bodyStart = (sep >= 0) ? sep + 2 : -1; }
                realBodySize = (bodyStart >= 0) ? content.length - bodyStart : content.length;
            } else {
                raw = new String(content);
            }
            lastParsed = HttpMessageParser.parse(raw, isRequest, realBodySize);

            // Check LRU cache for a pre-rendered document (skip expensive colorization)
            javax.swing.text.DefaultStyledDocument cachedDoc = docCache.get(contentHash);
            if (cachedDoc != null) {
                // Reuse cached document — instant, no re-colorization
                editor.setDocument(cachedDoc);
                reattachDocListeners(cachedDoc);
            } else {
                int totalLen = raw.length();
                if (totalLen > 30_000) {
                    // Large content: show plain text NOW, colorize in background
                    showPlainTextInstant(raw);
                    renderAsync(contentHash);
                } else {
                    // Small content: render offscreen synchronously (fast enough)
                    renderOffscreen();
                    if (editor.getDocument() instanceof javax.swing.text.DefaultStyledDocument) {
                        docCache.put(contentHash, (javax.swing.text.DefaultStyledDocument) editor.getDocument());
                    }
                }
            }

            lastContentHash = contentHash;
            editor.setCaretPosition(0);
            modified = false;
            updateStats();
            undoManager.discardAllEdits();
            editorHistory.save("Loaded " + (isRequest ? "request" : "response"), raw);
        } finally {
            this.updating = false;
        }
    }

    /**
     * Returns the editor content with {{template variables}} resolved.
     * The editor still shows {{var}} placeholders — only the output
     * sent to Burp (Repeater, Intruder, etc.) has real values.
     */
    public byte[] getContent() {
        String text = modified ? editor.getText() : (currentContent != null ? new String(currentContent) : "");
        // Normalize CRLF (Swing uses LF only, HTTP requires CRLF)
        text = normalizeCrlf(text);
        // Ensure trailing CRLF — HTTP requests must end with \r\n
        if (isRequest && !text.isEmpty() && !text.endsWith("\r\n")) {
            text += "\r\n";
        }
        // Apply template variables transparently before returning to Burp
        return TemplateVars.apply(text).getBytes();
    }

    public boolean isModified() { return modified; }

    public byte[] getSelectedData() {
        String sel = editor.getSelectedText();
        return sel != null ? sel.getBytes() : null;
    }

    /**
     * Almacena el contenido del companion (request si este es response, y viceversa)
     * para mostrarlo junto en la ventana Snap.
     */
    public void setCompanion(byte[] content, boolean isRequest) {
        this.companionContent = content;
        this.companionIsRequest = isRequest;
        // Reset companion minimize state
        this.companionOriginalHeaders = null;
        this.companionOriginalStartLine = null;
        this.companionOriginalBody = null;
        this.companionHiddenHeaderKeys = null;
        if (content != null && content.length > 0) {
            try {
                this.companionParsed = HttpMessageParser.parse(new String(content), isRequest);
            } catch (Exception e) {
                this.companionParsed = null;
            }
        } else {
            this.companionParsed = null;
        }
    }

    // ── Binary fast-path ─────────────────────────────────────────────

    /** Quickly scan raw bytes for binary content-type headers (PDF, image, octet-stream, etc.)
     *  without converting the full byte[] to String. Only checks the first 4KB (headers). */
    private static boolean quickBinaryCheck(byte[] content) {
        if (content.length < 100) return false;
        // Only scan the first 4KB for headers
        int scanLen = Math.min(content.length, 4096);
        String headerArea = new String(content, 0, scanLen, StandardCharsets.ISO_8859_1).toLowerCase();
        // Must have a header separator
        int sep = headerArea.indexOf("\r\n\r\n");
        if (sep < 0) sep = headerArea.indexOf("\n\n");
        if (sep < 0) return false;
        String headers = headerArea.substring(0, sep);
        int ctIdx = headers.indexOf("content-type:");
        if (ctIdx < 0) return false;
        String ctLine = headers.substring(ctIdx + 13);
        ctLine = ctLine.split("\\r?\\n")[0].trim();
        return ctLine.contains("pdf") || ctLine.contains("image/") || ctLine.contains("octet-stream")
                || ctLine.contains("video/") || ctLine.contains("audio/") || ctLine.contains("font/")
                || ctLine.contains("zip") || ctLine.contains("gzip") || ctLine.contains("woff")
                || ctLine.contains("protobuf") || ctLine.contains("grpc") || ctLine.contains("wasm")
                || ctLine.contains("x-shockwave") || ctLine.contains("x-executable")
                || ctLine.contains("x-msdos") || ctLine.contains("x-msdownload");
    }

    /** Build a truncated raw string: full headers + only first 128 bytes of body.
     *  This avoids converting multi-MB binary payloads to String. */
    private static String buildTruncatedRaw(byte[] content) {
        String full = new String(content, 0, Math.min(content.length, 4096), StandardCharsets.ISO_8859_1);
        int sep = full.indexOf("\r\n\r\n");
        int bodyStart = (sep >= 0) ? sep + 4 : -1;
        if (bodyStart < 0) {
            sep = full.indexOf("\n\n");
            bodyStart = (sep >= 0) ? sep + 2 : -1;
        }
        if (bodyStart < 0) return full;
        // Convert only headers + first 128 body bytes
        int endPos = Math.min(content.length, bodyStart + 128);
        return new String(content, 0, endPos, StandardCharsets.ISO_8859_1);
    }

    // ── Renderizado ─────────────────────────────────────────────────

    /**
     * Renders the current parsed message with syntax highlighting.
     * For large content, renders into an off-screen document first,
     * then swaps it into the editor atomically (no per-token repaints).
     */
    private void renderWithOverlays() {
        if (lastParsed == null) return;
        // Always render off-screen into a NEW document to avoid overwriting cached documents
        renderOffscreen();
    }

    /**
     * Show plain (uncolorized) text instantly so the user sees content immediately.
     * Used as a placeholder while async colorization runs in background.
     */
    private void showPlainTextInstant(String raw) {
        boolean wasUpdating = updating;
        updating = true;
        try {
            javax.swing.text.DefaultStyledDocument plainDoc = new javax.swing.text.DefaultStyledDocument();
            javax.swing.text.SimpleAttributeSet plainAttr = new javax.swing.text.SimpleAttributeSet();
            javax.swing.text.StyleConstants.setForeground(plainAttr, theme.fg);
            javax.swing.text.StyleConstants.setFontFamily(plainAttr, theme.editorFont.getFamily());
            javax.swing.text.StyleConstants.setFontSize(plainAttr, theme.editorFont.getSize());
            plainDoc.insertString(0, raw, plainAttr);
            editor.setDocument(plainDoc);
            reattachDocListeners(plainDoc);
        } catch (Exception ignored) {
        } finally {
            updating = wasUpdating;
        }
    }

    /**
     * Colorize in a background thread, then swap the colorized document into the editor.
     * The user sees plain text immediately; colorized version replaces it when ready.
     */
    private void renderAsync(final int contentHash) {
        final ParsedHttpMessage parsed = lastParsed;
        final ProColorTheme t = theme;
        final boolean pretty = prettyMode;
        final String hlWords = highlightField != null ? highlightField.getText() : "";
        final String blurWords = blurField != null ? blurField.getText() : "";

        asyncRenderWorker = new SwingWorker<javax.swing.text.DefaultStyledDocument, Void>() {
            @Override
            protected javax.swing.text.DefaultStyledDocument doInBackground() throws Exception {
                // Render into a fresh document OFF the EDT
                javax.swing.text.DefaultStyledDocument offDoc = new javax.swing.text.DefaultStyledDocument();
                HttpColorizer.render(offDoc, parsed, t, pretty);
                if (!hlWords.isBlank()) OverlayManager.applyHighlights(offDoc, hlWords, t);
                if (!blurWords.isBlank()) OverlayManager.applyBlur(offDoc, blurWords, t);
                return offDoc;
            }

            @Override
            protected void done() {
                if (isCancelled()) return;
                try {
                    javax.swing.text.DefaultStyledDocument colorDoc = get();
                    // Only swap if the user hasn't navigated to a different item
                    if (lastParsed == parsed) {
                        boolean wasUpdating = updating;
                        updating = true;
                        try {
                            editor.setDocument(colorDoc);
                            reattachDocListeners(colorDoc);
                            editor.setCaretPosition(0);
                            docCache.put(contentHash, colorDoc);
                        } finally {
                            updating = wasUpdating;
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        };
        asyncRenderWorker.execute();
    }

    /** Render directly into the editor's document (fast for small content) */
    private void renderInPlace() {
        boolean wasUpdating = updating;
        updating = true;
        try {
            HttpColorizer.render(editor.getStyledDocument(), lastParsed, theme, prettyMode);
            String hlWords = highlightField != null ? highlightField.getText() : "";
            if (!hlWords.isBlank()) OverlayManager.applyHighlights(editor.getStyledDocument(), hlWords, theme);
            String blurWords = blurField != null ? blurField.getText() : "";
            if (!blurWords.isBlank()) OverlayManager.applyBlur(editor.getStyledDocument(), blurWords, theme);
        } finally {
            updating = wasUpdating;
        }
    }

    /**
     * Render into a NEW off-screen document (no listeners, no repaints),
     * then swap it into the editor in one shot.
     * This eliminates the per-token repaint lag for large responses.
     */
    private void renderOffscreen() {
        boolean wasUpdating = updating;
        updating = true;
        try {
            // Create a fresh document with no listeners attached
            javax.swing.text.DefaultStyledDocument offDoc = new javax.swing.text.DefaultStyledDocument();

            // Render colorized content into the off-screen document
            HttpColorizer.render(offDoc, lastParsed, theme, prettyMode);

            // Apply overlays
            String hlWords = highlightField != null ? highlightField.getText() : "";
            if (!hlWords.isBlank()) OverlayManager.applyHighlights(offDoc, hlWords, theme);
            String blurWords = blurField != null ? blurField.getText() : "";
            if (!blurWords.isBlank()) OverlayManager.applyBlur(offDoc, blurWords, theme);

            // Swap the document into the editor — single atomic operation
            editor.setDocument(offDoc);

            // Re-attach listeners to the new document (single instances — no duplication)
            reattachDocListeners(offDoc);

        } finally {
            updating = wasUpdating;
        }
    }

    /**
     * Re-attach document listeners after swapping a document into the editor.
     * Removes existing listeners first to prevent accumulation on cached docs.
     */
    private void reattachDocListeners(javax.swing.text.DefaultStyledDocument doc) {
        // Remove first to prevent duplication on cached documents
        doc.removeUndoableEditListener(undoManager);
        doc.removeDocumentListener(docModListener);
        if (lineGutter != null) doc.removeDocumentListener(lineGutter);

        // Re-add
        doc.addUndoableEditListener(undoManager);
        doc.addDocumentListener(docModListener);
        if (lineGutter != null) {
            doc.addDocumentListener(lineGutter);
            lineGutter.changedUpdate(null);
        }
    }

    // ── Editor ──────────────────────────────────────────────────────

    private WrapTextPane createEditor() {
        WrapTextPane pane = new WrapTextPane();
        pane.setEditorKit(new WrapEditorKit());
        pane.setEditable(true);
        pane.setEnabled(true);
        pane.setFocusable(true);
        pane.setFont(theme.editorFont);
        pane.setBackground(theme.bg);
        pane.setForeground(theme.fg);
        pane.setCaretColor(theme.caret);
        pane.setSelectionColor(theme.selection);
        pane.setSelectedTextColor(theme.isDark() ? Color.WHITE : Color.BLACK);
        DefaultCaret caret = (DefaultCaret) pane.getCaret();
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
        caret.setVisible(true);
        caret.setBlinkRate(500);

        // Context menu (clic derecho)
        pane.setComponentPopupMenu(createContextMenu(pane));
        return pane;
    }

    private JPopupMenu createContextMenu(WrapTextPane pane) {
        JPopupMenu menu = new JPopupMenu();
        menu.setBackground(theme.bg);

        // ── Burp Actions (top, like native Burp) ──
        JMenuItem sendRepeater = new JMenuItem("Send to Repeater");
        sendRepeater.addActionListener(e -> sendToRepeater());
        JMenuItem sendIntruder = new JMenuItem("Send to Intruder");
        sendIntruder.addActionListener(e -> sendToIntruder());
        JMenuItem sendOrganizer = new JMenuItem("Send to Organizer");
        sendOrganizer.addActionListener(e -> sendToOrganizer());
        JMenuItem sendComparer = new JMenuItem("Send to Comparer");
        sendComparer.addActionListener(e -> sendToComparer());
        JMenuItem createIssue = new JMenuItem("Create issue...");
        createIssue.addActionListener(e -> createScanIssue());

        JMenuItem insertCollab = new JMenuItem("Insert Collaborator Payload");
        insertCollab.addActionListener(e -> insertCollaboratorPayload());
        JMenuItem openInBrowser = new JMenuItem("Open response in browser");
        openInBrowser.addActionListener(e -> openResponseInBrowser());

        menu.add(sendRepeater);
        menu.add(sendIntruder);
        menu.add(sendOrganizer);
        menu.add(sendComparer);
        menu.addSeparator();
        menu.add(createIssue);
        menu.add(insertCollab);
        menu.add(openInBrowser);
        menu.addSeparator();

        // ── Engagement tools (submenu) ──
        JMenu engagementMenu = new JMenu("Engagement tools");
        JMenuItem csrfPoc = new JMenuItem("Generate CSRF PoC...");
        csrfPoc.addActionListener(e -> generateCsrfPoc());
        JMenuItem findComments = new JMenuItem("Find comments");
        findComments.addActionListener(e -> findCommentsInResponse());
        JMenuItem findScripts = new JMenuItem("Find scripts");
        findScripts.addActionListener(e -> findScriptsInResponse());
        JMenuItem findForms = new JMenuItem("Find forms");
        findForms.addActionListener(e -> findFormsInResponse());
        engagementMenu.add(csrfPoc);
        engagementMenu.add(findComments);
        engagementMenu.add(findScripts);
        engagementMenu.add(findForms);
        menu.add(engagementMenu);

        // ── Change Request (submenu) ──
        JMenu changeReqMenu = new JMenu("Change Request");

        JMenuItem toJson = new JMenuItem("→ JSON (POST, application/json)");
        toJson.addActionListener(e -> changeRequestFormat("JSON"));
        JMenuItem toUrlEncoded = new JMenuItem("→ URL Encoded (POST, x-www-form-urlencoded)");
        toUrlEncoded.addActionListener(e -> changeRequestFormat("FORM"));
        JMenuItem toXml = new JMenuItem("→ XML (POST, application/xml)");
        toXml.addActionListener(e -> changeRequestFormat("XML"));
        JMenuItem toMultipart = new JMenuItem("→ Multipart (POST, multipart/form-data)");
        toMultipart.addActionListener(e -> changeRequestFormat("MULTIPART"));
        JMenuItem toGetNoBody = new JMenuItem("→ GET (move params to URL)");
        toGetNoBody.addActionListener(e -> changeRequestFormat("GET"));

        changeReqMenu.add(toJson);
        changeReqMenu.add(toUrlEncoded);
        changeReqMenu.add(toXml);
        changeReqMenu.add(toMultipart);
        changeReqMenu.addSeparator();
        changeReqMenu.add(toGetNoBody);

        menu.add(changeReqMenu);

        // ── Extensions (submenu — Pro Color tools) ──
        JMenu extensionsMenu = new JMenu("Extensions");
        menu.add(extensionsMenu);
        menu.addSeparator();

        // ── Copy URL ──
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> copyRequestUrl());
        menu.add(copyUrl);
        menu.addSeparator();

        // ── Edit (NO setAccelerator — solo mostrar texto del shortcut) ──
        String modText = IS_MAC ? "\u2318" : "Ctrl+";
        JMenuItem copy = new JMenuItem("Copy              " + modText + "C");
        copy.addActionListener(e -> pane.copy());
        JMenuItem cut = new JMenuItem("Cut                " + modText + "X");
        cut.addActionListener(e -> pane.cut());
        JMenuItem paste = new JMenuItem("Paste             " + modText + "V");
        paste.addActionListener(e -> pane.paste());
        JMenuItem selAll = new JMenuItem("Select All        " + modText + "A");
        selAll.addActionListener(e -> pane.selectAll());

        menu.add(copy);
        menu.add(cut);
        menu.add(paste);
        menu.addSeparator();
        menu.add(selAll);
        menu.addSeparator();

        // ── Undo / Redo ──
        JMenuItem undoItem = new JMenuItem("Undo              " + modText + "Z");
        undoItem.addActionListener(e -> undo());
        JMenuItem redoItem = new JMenuItem("Redo              " + modText + "Y");
        redoItem.addActionListener(e -> redo());
        menu.add(undoItem);
        menu.add(redoItem);
        menu.addSeparator();

        // ── Template Variables ──
        JMenu varsMenu = new JMenu("Template Variables");
        JMenuItem varsManager = new JMenuItem("Manage Variables...  " + modText + "T");
        varsManager.addActionListener(e -> openTemplateVarsManager());
        JMenuItem varsQuickSet = new JMenuItem("Set Selection as Variable...");
        varsQuickSet.addActionListener(e -> quickSetVariable());
        JMenuItem varsUse = new JMenuItem("Insert Variable Here...");
        varsUse.addActionListener(e -> insertVariableAtCaret());
        JMenuItem varsInfo = new JMenuItem("Auto-replaced on Send to Repeater/Intruder");
        varsInfo.setEnabled(false);
        varsInfo.setFont(varsInfo.getFont().deriveFont(Font.ITALIC));
        varsMenu.add(varsManager);
        varsMenu.add(varsQuickSet);
        varsMenu.add(varsUse);
        varsMenu.addSeparator();
        varsMenu.add(varsInfo);
        menu.add(varsMenu);

        // ── History ──
        JMenuItem historyItem = new JMenuItem("Editor History...");
        historyItem.addActionListener(e -> showHistory());
        JMenuItem saveSnapItem = new JMenuItem("Save Snapshot");
        saveSnapItem.addActionListener(e -> saveManualSnapshot());
        menu.add(historyItem);
        menu.add(saveSnapItem);

        // Habilitar/deshabilitar + poblar Extensions dinámicamente
        menu.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) {
                boolean hasSel = pane.getSelectedText() != null;
                boolean hasContent = pane.getDocument().getLength() > 0;
                boolean hasRequest = hasContent && getRequestBytes() != null;
                // Burp actions
                sendRepeater.setEnabled(hasRequest);
                sendIntruder.setEnabled(hasRequest);
                sendOrganizer.setEnabled(hasRequest);
                sendComparer.setEnabled(hasContent);
                createIssue.setEnabled(hasRequest);
                insertCollab.setEnabled(isRequest && hasContent);
                openInBrowser.setEnabled(hasContent && !isRequest);
                copyUrl.setEnabled(hasRequest);
                // Engagement
                csrfPoc.setEnabled(hasRequest);
                findComments.setEnabled(hasContent);
                findScripts.setEnabled(hasContent);
                findForms.setEnabled(hasContent);
                engagementMenu.setEnabled(hasContent);
                changeReqMenu.setEnabled(hasRequest && isRequest);
                // Edit
                copy.setEnabled(hasSel);
                cut.setEnabled(hasSel);
                undoItem.setEnabled(undoManager.canUndo());
                redoItem.setEnabled(undoManager.canRedo());
                // Template vars
                varsQuickSet.setEnabled(hasSel);
                varsUse.setEnabled(!TemplateVars.getAll().isEmpty());
                historyItem.setEnabled(editorHistory.size() > 0);

                // Poblar Extensions dinámicamente
                populateExtensionsMenu(extensionsMenu, hasContent);
            }
            @Override public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {}
            @Override public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {}
        });

        return menu;
    }

    /**
     * Puebla el submenu Extensions con las herramientas de Pro Color View.
     * Nota: La Montoya API no expone un método para listar extensiones
     * instaladas, así que solo mostramos las propias.
     */
    private void populateExtensionsMenu(JMenu extensionsMenu, boolean hasContent) {
        extensionsMenu.removeAll();

        // Header informativo
        JMenuItem header = new JMenuItem("Pro Color View");
        header.setEnabled(false);
        header.setFont(header.getFont().deriveFont(Font.BOLD));
        extensionsMenu.add(header);
        extensionsMenu.addSeparator();

        JMenuItem curlItem = new JMenuItem("Copy as cURL");
        curlItem.addActionListener(e -> copyAsCurl());
        curlItem.setEnabled(hasContent && lastParsed != null && lastParsed.isRequest());
        JMenuItem jwtItem = new JMenuItem("JWT Decode");
        jwtItem.addActionListener(e -> decodeJwt());
        jwtItem.setEnabled(hasContent);
        JMenuItem secretsItem = new JMenuItem("Find Secrets");
        secretsItem.addActionListener(e -> findSecrets());
        secretsItem.setEnabled(hasContent);
        JMenuItem linksItem = new JMenuItem("Find Links");
        linksItem.addActionListener(e -> findLinks());
        linksItem.setEnabled(hasContent);
        JMenuItem minimizeItem = new JMenuItem("Minimize Headers...");
        minimizeItem.addActionListener(e -> minimizeHeaders());
        minimizeItem.setEnabled(hasContent && lastParsed != null);
        JMenuItem snapItem = new JMenuItem("Snap (Screenshot)");
        snapItem.addActionListener(e -> openSnapWindow());
        snapItem.setEnabled(hasContent);
        JMenuItem exportItem = new JMenuItem("Export to File");
        exportItem.addActionListener(e -> exportToFile());
        exportItem.setEnabled(hasContent);

        extensionsMenu.add(curlItem);
        extensionsMenu.add(jwtItem);
        extensionsMenu.add(secretsItem);
        extensionsMenu.add(linksItem);
        extensionsMenu.add(minimizeItem);
        extensionsMenu.addSeparator();
        JMenuItem varsItem = new JMenuItem("Template Variables...");
        varsItem.addActionListener(e -> openTemplateVarsManager());
        JMenuItem histItem = new JMenuItem("Editor History...");
        histItem.addActionListener(e -> showHistory());
        histItem.setEnabled(editorHistory.size() > 0);
        extensionsMenu.add(varsItem);
        extensionsMenu.add(histItem);
        extensionsMenu.addSeparator();
        extensionsMenu.add(snapItem);
        extensionsMenu.add(exportItem);

        extensionsMenu.setEnabled(true);
    }

    private JScrollPane createScrollPane(boolean wrapEnabled) {
        JScrollPane sp = new JScrollPane(editor);
        sp.getViewport().setBackground(theme.bg);
        sp.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        sp.setHorizontalScrollBarPolicy(wrapEnabled
                ? ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER
                : ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        return sp;
    }

    // ── Toolbar ─────────────────────────────────────────────────────

    private JPanel createToolbar() {
        // Use WrapLayout so the toolbar wraps when the window is narrow
        JPanel toolbar = new JPanel(new WrapLayout(FlowLayout.LEFT, 3, 2));
        toolbar.setBackground(theme.bg);
        toolbar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0,
                        theme.isDark() ? new Color(60, 60, 60) : new Color(200, 200, 200)),
                BorderFactory.createEmptyBorder(2, 4, 2, 4)
        ));

        // ── Search group ──
        searchField = field(10, "Buscar (live search)");
        replaceField = field(10, "Reemplazar por...");

        JButton prevBtn = btn("\u25C0", "Anterior");
        JButton nextBtn = btn("\u25B6", "Siguiente");
        prevBtn.addActionListener(e -> searchPrev());
        nextBtn.addActionListener(e -> searchNext());

        JButton replBtn = btn("Repl", "Reemplazar actual");
        JButton replAllBtn = btn("All", "Reemplazar todos");
        replBtn.addActionListener(e -> replaceCurrent());
        replAllBtn.addActionListener(e -> replaceAll());

        searchStatus = new JLabel(" ");
        searchStatus.setForeground(theme.bodyHint);
        searchStatus.setFont(theme.editorFont.deriveFont(11f));

        toolbar.add(label("\uD83D\uDD0D"));
        toolbar.add(searchField);
        toolbar.add(prevBtn);
        toolbar.add(nextBtn);
        toolbar.add(sep());
        toolbar.add(replaceField);
        toolbar.add(replBtn);
        toolbar.add(replAllBtn);
        toolbar.add(searchStatus);
        toolbar.add(sep());

        searchField.addActionListener(e -> searchNext());
        replaceField.addActionListener(e -> replaceCurrent());
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { liveSearch(); }
            @Override public void removeUpdate(DocumentEvent e)  { liveSearch(); }
            @Override public void changedUpdate(DocumentEvent e) { liveSearch(); }
        });

        // ── Overlay group ──
        highlightField = field(8, "Highlight CSV");
        blurField = field(8, "Blur CSV");
        JButton applyBtn = btn("Aplicar", "Aplicar highlight y blur");
        applyBtn.addActionListener(e -> applyOverlays());

        JLabel hlL = label("HL:");
        hlL.setForeground(new Color(255, 214, 102));
        JLabel blurL = label("Blur:");
        blurL.setForeground(new Color(180, 180, 210));

        toolbar.add(hlL);
        toolbar.add(highlightField);
        toolbar.add(blurL);
        toolbar.add(blurField);
        toolbar.add(applyBtn);
        toolbar.add(sep());

        // ── View controls group ──
        wrapCheckbox = check("Wrap", true, "Ajuste de línea");
        wrapCheckbox.addActionListener(e -> toggleWrap());

        linesCheckbox = check("#", true, "Números de línea");
        linesCheckbox.addActionListener(e -> toggleLineNumbers());

        prettyBtn = btn("Pretty", "Beautify/Minify (" + (IS_MAC ? "Cmd" : "Ctrl") + "+B)");
        prettyBtn.addActionListener(e -> togglePretty());

        JButton undoBtn = btn("\u21A9", "Deshacer");
        JButton redoBtn = btn("\u21AA", "Rehacer");
        undoBtn.addActionListener(e -> undo());
        redoBtn.addActionListener(e -> redo());

        toolbar.add(wrapCheckbox);
        toolbar.add(linesCheckbox);
        toolbar.add(prettyBtn);
        toolbar.add(sep());
        toolbar.add(undoBtn);
        toolbar.add(redoBtn);
        toolbar.add(sep());

        // ── Template Variables & History ──
        JButton varsBtn = btn("{{x}}", "Template Variables — define variables (" + (IS_MAC ? "Cmd" : "Ctrl") + "+T). Auto-replaced on Send.");
        varsBtn.setForeground(new Color(124, 211, 255));
        varsBtn.addActionListener(e -> openTemplateVarsManager());

        JButton historyBtn = btn("\u23F3", "Editor History — browse and restore versions");
        historyBtn.addActionListener(e -> showHistory());

        JButton saveSnapBtn = btn("\uD83D\uDCBE", "Save snapshot of current content");
        saveSnapBtn.addActionListener(e -> saveManualSnapshot());

        JButton minimizeBtn = btn("\u2702", "Minimize Headers — remove unnecessary headers");
        minimizeBtn.addActionListener(e -> minimizeHeaders());

        JButton colorsBtn = btn("\uD83C\uDFA8", "Configure parameter colors (URL params & form body)");
        colorsBtn.addActionListener(e -> {
            if (com.procolorview.util.ColorConfig.showConfigDialog(mainPanel, theme.isDark())) {
                // Clear cache and re-render to apply new colors
                docCache.clear();
                lastContentHash = 0;
                if (lastParsed != null) renderWithOverlays();
                searchStatus.setText("Parameter colors updated");
            }
        });

        // ── AI Testing ──
        JButton aiBtn = btn("\uD83E\uDD16 AI", "AI Vulnerability Testing");
        aiBtn.setForeground(new Color(255, 180, 60));
        aiBtn.setFont(theme.editorFont.deriveFont(Font.BOLD, 11f));
        aiBtn.addActionListener(e -> aiPanel.toggle());

        toolbar.add(varsBtn);
        toolbar.add(colorsBtn);
        toolbar.add(sep());
        toolbar.add(historyBtn);
        toolbar.add(saveSnapBtn);
        toolbar.add(sep());
        toolbar.add(minimizeBtn);
        toolbar.add(sep());
        toolbar.add(aiBtn);

        highlightField.addActionListener(e -> applyOverlays());
        blurField.addActionListener(e -> applyOverlays());

        return toolbar;
    }

    // ══════════════════════════════════════════════════════════════════
    //  DECODER PANEL — Bidireccional: decode ↔ encode en vivo
    // ══════════════════════════════════════════════════════════════════

    /**
     * Panel inferior que aparece al seleccionar texto.
     *
     * Layout: [ComboBox encoding ▼] [===== editable text =====] [Copy]
     *
     * - Si el texto seleccionado ES codificado: muestra decodificado (editable)
     *   → al editarlo se re-codifica y reemplaza la selección en el editor
     * - Si NO es codificado: muestra encodings comunes (read-only info)
     */
    private JPanel createDecoderPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        Color panelBg = theme.isDark() ? new Color(22, 26, 34) : new Color(245, 247, 250);
        panel.setBackground(panelBg);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0,
                        theme.isDark() ? new Color(60, 60, 60) : new Color(200, 200, 200)),
                BorderFactory.createEmptyBorder(3, 6, 3, 6)
        ));

        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(1, 2, 1, 2);
        g.gridy = 0;

        // Combo box para seleccionar encoding
        decoderCombo = new JComboBox<>();
        decoderCombo.setFont(theme.editorFont.deriveFont(Font.BOLD, 10f));
        decoderCombo.setBackground(theme.searchFieldBg);
        decoderCombo.setForeground(theme.isDark() ? new Color(124, 211, 255) : new Color(0, 105, 170));
        decoderCombo.setPreferredSize(new Dimension(100, 24));
        decoderCombo.addActionListener(e -> {
            if (!decoderBusy) onComboChanged();
        });

        // Text area editable para el contenido decodificado
        decoderText = new JTextArea(2, 40);
        decoderText.setFont(theme.editorFont.deriveFont(11f));
        decoderText.setBackground(panelBg);
        decoderText.setForeground(theme.fg);
        decoderText.setCaretColor(theme.caret);
        decoderText.setLineWrap(true);
        decoderText.setWrapStyleWord(true);

        // Listener: cuando el usuario edita el decoded text → re-encode al editor
        decoderText.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { onDecoderEdited(); }
            @Override public void removeUpdate(DocumentEvent e)  { onDecoderEdited(); }
            @Override public void changedUpdate(DocumentEvent e) {}
        });

        // Al perder foco del decoder, refrescar la selección del editor
        decoderText.addFocusListener(new FocusAdapter() {
            @Override public void focusLost(FocusEvent e) {
                // Pequeño delay para permitir que el caret del editor se actualice
                SwingUtilities.invokeLater(() -> updateDecoderPanel());
            }
        });

        JScrollPane sp = new JScrollPane(decoderText);
        sp.setBorder(BorderFactory.createLineBorder(
                theme.isDark() ? new Color(50, 55, 65) : new Color(210, 215, 220)));
        sp.setPreferredSize(new Dimension(0, 52));
        sp.getViewport().setBackground(panelBg);

        // Copy button
        decoderCopyBtn = new JButton("Copy");
        decoderCopyBtn.setFont(theme.editorFont.deriveFont(10f));
        decoderCopyBtn.setMargin(new Insets(1, 4, 1, 4));
        decoderCopyBtn.addActionListener(e -> {
            copyToClipboard(decoderText.getText());
            decoderCopyBtn.setText("OK!");
            if (feedbackTimer != null) feedbackTimer.stop();
            feedbackTimer = new Timer(1000, ev -> decoderCopyBtn.setText("Copy"));
            feedbackTimer.setRepeats(false);
            feedbackTimer.start();
        });

        g.gridx = 0; g.weightx = 0; g.fill = GridBagConstraints.NONE;
        panel.add(decoderCombo, g);

        g.gridx = 1; g.weightx = 1.0; g.fill = GridBagConstraints.BOTH;
        panel.add(sp, g);

        // Replace button — replaces selected text in editor with decoded/encoded value
        JButton decoderReplaceBtn = new JButton("Replace");
        decoderReplaceBtn.setFont(theme.editorFont.deriveFont(10f));
        decoderReplaceBtn.setMargin(new Insets(1, 4, 1, 4));
        decoderReplaceBtn.setForeground(theme.isDark() ? new Color(255, 200, 100) : new Color(180, 100, 0));
        decoderReplaceBtn.setToolTipText("Replace selected text in editor with this value");
        decoderReplaceBtn.addActionListener(e -> {
            String replacement = decoderText.getText();
            if (replacement == null || replacement.isEmpty()) return;
            if (decoderSelStart < 0 || decoderSelEnd < 0) return;
            decoderBusy = true;
            try {
                Document doc = editor.getDocument();
                int docLen = doc.getLength();
                int start = Math.min(decoderSelStart, docLen);
                int end = Math.min(decoderSelEnd, docLen);
                if (start > end) return;
                doc.remove(start, end - start);
                doc.insertString(start, replacement, null);
                decoderSelEnd = start + replacement.length();
                editor.select(start, decoderSelEnd);
                modified = true;
                decoderReplaceBtn.setText("OK!");
                if (feedbackTimer != null) feedbackTimer.stop();
                feedbackTimer = new Timer(1000, ev -> decoderReplaceBtn.setText("Replace"));
                feedbackTimer.setRepeats(false);
                feedbackTimer.start();
            } catch (BadLocationException ignored) {
            } finally {
                decoderBusy = false;
            }
        });

        g.gridx = 2; g.weightx = 0; g.fill = GridBagConstraints.NONE;
        panel.add(decoderReplaceBtn, g);

        g.gridx = 3; g.weightx = 0; g.fill = GridBagConstraints.NONE;
        panel.add(decoderCopyBtn, g);

        panel.setVisible(false);
        return panel;
    }

    /**
     * Se ejecuta al cambiar la selección en el editor.
     * Detecta encodings, puebla el combo y muestra el decode.
     */
    private void updateDecoderPanel() {
        if (decoderBusy) return;

        String selected = editor.getSelectedText();
        if (selected == null || selected.strip().length() < 4) {
            hideDecoder();
            return;
        }

        String trimmed = selected.strip();
        decoderBusy = true;
        try {
            // Guardar posiciones de la selección en el editor
            decoderSelStart = editor.getSelectionStart();
            decoderSelEnd   = editor.getSelectionEnd();

            // Intentar decodificar
            Map<String, String> decoded = Decoder.decodeAll(trimmed);

            if (!decoded.isEmpty()) {
                // MODO DECODE: el texto está codificado
                isDecodeMode = true;
                currentResults = decoded;
                populateCombo(decoded);
                String firstKey = decoded.keySet().iterator().next();
                decoderText.setText(decoded.get(firstKey));
                decoderText.setCaretPosition(0);
                decoderText.setEditable(!"JWT".equals(firstKey)); // JWT no es re-encodeable
                showDecoder();
            } else if (trimmed.length() <= 500) {
                // MODO ENCODE: texto plano, mostrar encodings
                isDecodeMode = false;
                Map<String, String> encoded = Decoder.encodeAll(trimmed);
                currentResults = encoded;
                populateCombo(encoded);
                if (!encoded.isEmpty()) {
                    String firstKey = encoded.keySet().iterator().next();
                    decoderText.setText(encoded.get(firstKey));
                    decoderText.setCaretPosition(0);
                    decoderText.setEditable(false); // encode mode es read-only
                    showDecoder();
                } else {
                    hideDecoder();
                }
            } else {
                hideDecoder();
            }
        } finally {
            decoderBusy = false;
        }
    }

    /**
     * Se ejecuta cuando el usuario cambia el tipo de encoding en el combo.
     */
    private void onComboChanged() {
        if (decoderBusy || decoderCombo.getSelectedItem() == null) return;

        String key = (String) decoderCombo.getSelectedItem();
        String value = currentResults.get(key);
        if (value == null) return;

        decoderBusy = true;
        try {
            decoderText.setText(value);
            decoderText.setCaretPosition(0);
            // JWT no es re-encodeable
            decoderText.setEditable(isDecodeMode && !"JWT".equals(key));
        } finally {
            decoderBusy = false;
        }
    }

    /**
     * Se ejecuta cada vez que el usuario edita el texto decodificado.
     * Re-codifica el contenido editado y lo reemplaza en el editor.
     */
    private void onDecoderEdited() {
        if (decoderBusy || !isDecodeMode) return;
        if (decoderSelStart < 0 || decoderSelEnd < 0) return;

        String selectedEncoding = (String) decoderCombo.getSelectedItem();
        if (selectedEncoding == null || "JWT".equals(selectedEncoding)) return;

        String editedText = decoderText.getText();
        String reEncoded = reEncode(editedText, selectedEncoding);
        if (reEncoded == null) return;

        decoderBusy = true;
        try {
            Document doc = editor.getDocument();
            int docLen = doc.getLength();

            // Validar posiciones
            if (decoderSelStart > docLen) decoderSelStart = docLen;
            if (decoderSelEnd > docLen) decoderSelEnd = docLen;
            if (decoderSelStart > decoderSelEnd) return;

            int oldLen = decoderSelEnd - decoderSelStart;
            doc.remove(decoderSelStart, oldLen);
            doc.insertString(decoderSelStart, reEncoded, null);

            // Actualizar posición del fin de la selección
            decoderSelEnd = decoderSelStart + reEncoded.length();

            // Mantener la selección en el editor para que se vea qué se reemplazó
            editor.select(decoderSelStart, decoderSelEnd);

            modified = true;

            // Actualizar el resultado en currentResults
            currentResults.put(selectedEncoding, editedText);
        } catch (BadLocationException ignored) {
        } finally {
            decoderBusy = false;
        }
    }

    /**
     * Re-codifica el texto editado usando el encoding especificado.
     */
    private String reEncode(String text, String encoding) {
        return switch (encoding) {
            case "Base64" -> Decoder.base64Encode(text);
            case "URL"    -> Decoder.urlEncode(text);
            case "Hex"    -> Decoder.hexEncode(text);
            case "HTML"   -> Decoder.htmlEncode(text);
            default       -> null;
        };
    }

    private void populateCombo(Map<String, String> results) {
        decoderCombo.removeAllItems();
        for (String key : results.keySet()) {
            decoderCombo.addItem(key);
        }
    }

    private void showDecoder() {
        if (!decoderPanel.isVisible()) {
            decoderPanel.setVisible(true);
            mainPanel.revalidate();
        }
    }

    private void hideDecoder() {
        if (decoderPanel.isVisible()) {
            decoderPanel.setVisible(false);
            decoderSelStart = -1;
            decoderSelEnd = -1;
            mainPanel.revalidate();
        }
    }

    // ── Status bar ──────────────────────────────────────────────────

    private JPanel createStatusBar() {
        JPanel bar = new JPanel();
        bar.setLayout(new BoxLayout(bar, BoxLayout.X_AXIS));
        bar.setBackground(theme.bg);
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0,
                        theme.isDark() ? new Color(60, 60, 60) : new Color(200, 200, 200)),
                BorderFactory.createEmptyBorder(1, 4, 1, 4)
        ));

        statsLabel = new JLabel(" ");
        statsLabel.setFont(theme.editorFont.deriveFont(10.5f));
        statsLabel.setForeground(theme.bodyHint);
        bar.add(statsLabel);
        bar.add(Box.createHorizontalGlue()); // push buttons to the right

        // Buttons inline — BoxLayout keeps them compact on the right
        JButton curlBtn = sBtn("cURL", "Copiar request como cURL mínimo");
        curlBtn.addActionListener(e -> copyAsCurl());
        JButton jwtBtn = sBtn("JWT", "Escanear todos los JWT del contenido");
        jwtBtn.addActionListener(e -> decodeJwt());
        JButton secretsBtn = sBtn("Secrets", "Buscar API keys, tokens, passwords, private keys...");
        secretsBtn.addActionListener(e -> findSecrets());
        JButton linksBtn = sBtn("Links", "Extraer URLs, paths, endpoints, subdominios...");
        linksBtn.addActionListener(e -> findLinks());
        JButton exportBtn = sBtn("Export", "Guardar a archivo");
        exportBtn.addActionListener(e -> exportToFile());
        JButton snapBtn = sBtn("Snap", "Screenshot view (" + (IS_MAC ? "Cmd" : "Ctrl") + "+Shift+S)");
        snapBtn.addActionListener(e -> openSnapWindow());
        JButton varsBarBtn = sBtn("{{x}}", "Template Variables");
        varsBarBtn.setForeground(new Color(124, 211, 255));
        varsBarBtn.addActionListener(e -> openTemplateVarsManager());
        JButton histBarBtn = sBtn("\u23F3 Hist", "Editor History");
        histBarBtn.addActionListener(e -> showHistory());

        bar.add(curlBtn);  bar.add(sBarSep());
        bar.add(jwtBtn);   bar.add(sBarSep());
        bar.add(secretsBtn); bar.add(sBarSep());
        bar.add(linksBtn);  bar.add(sBarSep());
        bar.add(exportBtn); bar.add(sBarSep());
        bar.add(snapBtn);  bar.add(sBarSep());
        bar.add(varsBarBtn); bar.add(sBarSep());
        bar.add(histBarBtn);
        return bar;
    }

    /** Thin separator dot for the status bar */
    private JLabel sBarSep() {
        JLabel l = new JLabel("\u00B7");
        l.setForeground(theme.isDark() ? new Color(80, 80, 80) : new Color(180, 180, 180));
        l.setFont(theme.editorFont.deriveFont(10f));
        return l;
    }

    private void updateStats() {
        SwingUtilities.invokeLater(() -> {
            try {
                int len = editor.getDocument().getLength();
                String text = editor.getDocument().getText(0, len);
                long lines = text.chars().filter(ch -> ch == '\n').count() + 1;
                String bt = (lastParsed != null) ? lastParsed.bodyType().name() : "\u2014";
                String mode = prettyMode ? "Pretty" : "Minify";
                // Selection info
                String sel = editor.getSelectedText();
                String selInfo = "";
                if (sel != null && !sel.isEmpty()) {
                    long selLines = sel.chars().filter(ch -> ch == '\n').count() + 1;
                    selInfo = " | Sel: %d chars".formatted(sel.length());
                    if (selLines > 1) selInfo += ", %d lines".formatted(selLines);
                }
                statsLabel.setText("  Lines: %d | Chars: %d | Body: %s | %s%s".formatted(lines, len, bt, mode, selInfo));
            } catch (Exception e) { statsLabel.setText(" "); }
        });
    }

    // ── Component helpers ───────────────────────────────────────────

    private GridBagConstraints gbc() {
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(1, 2, 1, 2);
        g.fill = GridBagConstraints.HORIZONTAL;
        g.gridy = 0;
        return g;
    }
    private JTextField field(int cols, String tip) {
        JTextField tf = new JTextField(cols);
        tf.setBackground(theme.searchFieldBg); tf.setForeground(theme.fg);
        tf.setCaretColor(theme.caret); tf.setToolTipText(tip);
        tf.setMinimumSize(new Dimension(60, 24));
        return tf;
    }
    private JCheckBox check(String text, boolean sel, String tip) {
        JCheckBox cb = new JCheckBox(text, sel);
        cb.setBackground(theme.bg); cb.setForeground(theme.fg);
        cb.setToolTipText(tip); cb.setFocusPainted(false);
        cb.setMargin(new Insets(0, 2, 0, 2));
        return cb;
    }
    private JLabel label(String t) {
        JLabel l = new JLabel(t); l.setForeground(theme.bodyHint); return l;
    }
    private JButton btn(String t, String tip) {
        JButton b = new JButton(t); b.setBackground(theme.searchFieldBg);
        b.setForeground(theme.fg); b.setFocusPainted(false);
        b.setMargin(new Insets(2, 6, 2, 6)); b.setToolTipText(tip); return b;
    }
    private JButton sBtn(String t, String tip) {
        JButton b = new JButton(t); b.setBackground(theme.bg);
        b.setForeground(theme.bodyHint); b.setFocusPainted(false);
        b.setBorderPainted(false); b.setMargin(new Insets(0, 4, 0, 4));
        b.setFont(theme.editorFont.deriveFont(10f)); b.setToolTipText(tip);
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)); return b;
    }
    private JSeparator sep() {
        JSeparator s = new JSeparator(SwingConstants.VERTICAL);
        s.setPreferredSize(new Dimension(1, 20));
        s.setForeground(theme.isDark() ? new Color(80, 80, 80) : new Color(180, 180, 180));
        return s;
    }

    // ── Overlays ────────────────────────────────────────────────────

    private void applyOverlays() {
        if (lastParsed == null) return;
        int pos = editor.getCaretPosition();
        renderWithOverlays();
        SwingUtilities.invokeLater(() -> {
            try { editor.setCaretPosition(Math.min(pos, editor.getDocument().getLength())); }
            catch (Exception ignored) {}
        });
    }

    // ── Search ──────────────────────────────────────────────────────

    private void liveSearch() {
        String q = searchField.getText();
        if (q.isEmpty()) { searchManager.clearMatchHighlights(); searchStatus.setText(" "); return; }
        searchManager.search(q, false);
        searchManager.highlightAllMatches();
        searchStatus.setText(searchManager.statusText());
    }
    private void searchNext() {
        String q = searchField.getText();
        if (q.isEmpty()) { searchStatus.setText(" "); return; }
        searchManager.search(q, false); searchManager.next();
        searchStatus.setText(searchManager.statusText());
    }
    private void searchPrev() {
        String q = searchField.getText();
        if (q.isEmpty()) { searchStatus.setText(" "); return; }
        searchManager.search(q, false); searchManager.prev();
        searchStatus.setText(searchManager.statusText());
    }

    // ── Replace ─────────────────────────────────────────────────────

    private void replaceCurrent() {
        String q = searchField.getText();
        if (q.isEmpty()) return;
        if (searchManager.totalMatches() == 0 || searchManager.currentIndex() < 0) {
            searchManager.search(q, false);
            if (searchManager.totalMatches() > 0) searchManager.next();
        }
        searchManager.replaceCurrent(replaceField.getText());
        searchStatus.setText(searchManager.statusText());
        modified = true;
    }
    private void replaceAll() {
        String q = searchField.getText();
        if (q.isEmpty()) return;
        editorHistory.save("Before Replace All '" + q + "'", editorText());
        int cnt = searchManager.replaceAll(q, replaceField.getText(), false);
        searchStatus.setText(cnt + " reemplazados");
        modified = true;
    }

    // ── Toggles ─────────────────────────────────────────────────────

    private void toggleWrap() {
        boolean on = wrapCheckbox.isSelected();
        int pos = editor.getCaretPosition();
        editor.setWrapEnabled(on);
        scrollPane.setHorizontalScrollBarPolicy(on
                ? ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER
                : ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        editor.revalidate(); editor.repaint();
        scrollPane.getViewport().revalidate(); scrollPane.revalidate(); scrollPane.repaint();
        mainPanel.revalidate(); mainPanel.repaint();
        SwingUtilities.invokeLater(() -> {
            try { editor.setCaretPosition(Math.min(pos, editor.getDocument().getLength()));
                  editor.requestFocusInWindow(); } catch (Exception ignored) {}
        });
    }
    private void toggleLineNumbers() {
        lineGutter.setGutterVisible(linesCheckbox.isSelected());
        scrollPane.setRowHeaderView(linesCheckbox.isSelected() ? lineGutter : null);
        scrollPane.revalidate(); scrollPane.repaint();
    }
    private void togglePretty() {
        editorHistory.save("Before " + (prettyMode ? "Minify" : "Pretty"), editorText());
        prettyMode = !prettyMode;
        lastContentHash = 0; // force re-render with new mode
        prettyBtn.setText(prettyMode ? "Pretty" : "Minify");
        if (lastParsed != null) {
            int pos = editor.getCaretPosition();
            renderWithOverlays();
            SwingUtilities.invokeLater(() -> {
                try { editor.setCaretPosition(Math.min(pos, editor.getDocument().getLength())); }
                catch (Exception ignored) {}
            });
        }
        updateStats();
    }

    // ── Burp actions ────────────────────────────────────────────────

    /**
     * Obtiene los bytes del request actual.
     * Si este editor muestra un request, usa currentContent.
     * Si muestra un response, usa companionContent (el request).
     */
    private byte[] getRequestBytes() {
        if (isRequest && currentContent != null) return currentContent;
        if (!isRequest && companionContent != null) return companionContent;
        return null;
    }

    /**
     * Builds an HttpRequest from raw bytes WITHOUT template variable replacement.
     * Used for cases where you want the raw request (e.g. Comparer, display).
     */
    private HttpRequest buildRequest() {
        byte[] reqBytes = getRequestBytes();
        if (reqBytes == null) return null;
        try {
            return HttpRequest.httpRequest(normalizeCrlf(new String(reqBytes)));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Builds an HttpRequest with {{template variables}} automatically replaced.
     * The editor content stays unchanged — only the SENT request has real values.
     * Used for Repeater, Intruder, Organizer, CSRF PoC, cURL export.
     */
    private HttpRequest buildRequestWithVars() {
        byte[] reqBytes = getRequestBytes();
        if (reqBytes == null) return null;
        try {
            String raw = new String(reqBytes);
            // If editor was modified, use editor text (for request editors)
            if (isRequest && modified) {
                raw = editorText();
            }
            // Normalize line endings to CRLF (Swing uses LF only)
            raw = normalizeCrlf(raw);
            // Apply template variables transparently
            String resolved = TemplateVars.apply(raw);
            return HttpRequest.httpRequest(resolved);
        } catch (Exception e) {
            return null;
        }
    }

    /** Normalize line endings: ensure all lines use CRLF as required by HTTP/1.1 */
    private static String normalizeCrlf(String raw) {
        // First remove any existing \r to avoid double \r\r\n, then add \r before every \n
        return raw.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n");
    }

    private void sendToRepeater() {
        HttpRequest req = buildRequestWithVars();
        if (req == null) { info("No request available."); return; }
        try {
            req = ensureService(req);
            String tabName = "Pro Color";
            if (lastParsed != null && lastParsed.isRequest() && lastParsed.startLine() != null) {
                String[] parts = lastParsed.startLine().strip().split("\\s+");
                if (parts.length >= 2) tabName = parts[0] + " " + parts[1];
            } else if (companionParsed != null && companionParsed.isRequest() && companionParsed.startLine() != null) {
                String[] parts = companionParsed.startLine().strip().split("\\s+");
                if (parts.length >= 2) tabName = parts[0] + " " + parts[1];
            }
            api.repeater().sendToRepeater(req, tabName);
            searchStatus.setText("Sent to Repeater!");
        } catch (Exception e) {
            info("Error sending to Repeater: " + e.getMessage());
        }
    }

    private void sendToIntruder() {
        HttpRequest req = buildRequestWithVars();
        if (req == null) { info("No request available."); return; }
        try {
            req = ensureService(req);
            api.intruder().sendToIntruder(req);
            searchStatus.setText("Sent to Intruder!");
        } catch (Exception e) {
            info("Error sending to Intruder: " + e.getMessage());
        }
    }

    /**
     * Ensures the HttpRequest has an HttpService attached (host/port/https).
     * Uses the original service from Burp first, then falls back to Host header parsing.
     */
    private HttpRequest ensureService(HttpRequest req) {
        // 1) Already has service? Done.
        if (req.httpService() != null && req.httpService().host() != null
                && !req.httpService().host().isEmpty()) {
            return req;
        }
        // 2) Use the original service stored when Burp set the request/response
        if (originalService != null) {
            return req.withService(originalService);
        }
        // 3) Fallback: parse Host header
        String host = req.headerValue("Host");
        if (host == null || host.isBlank()) return req;
        host = host.strip();
        boolean secure = false;
        int port = 80;
        if (host.contains(":")) {
            String[] parts = host.split(":", 2);
            host = parts[0];
            try { port = Integer.parseInt(parts[1]); } catch (NumberFormatException ignored) {}
            if (port == 443) secure = true;
        } else {
            // Default to HTTPS 443 since most pentest targets use it
            secure = true;
            port = 443;
        }
        return req.withService(HttpService.httpService(host, port, secure));
    }

    private void sendToOrganizer() {
        HttpRequest req = buildRequestWithVars();
        if (req == null) { info("No request available."); return; }
        try {
            req = ensureService(req);
            // Construir response si existe
            burp.api.montoya.http.message.responses.HttpResponse resp = null;
            byte[] respBytes = isRequest ? companionContent : currentContent;
            if (respBytes != null) {
                resp = burp.api.montoya.http.message.responses.HttpResponse.httpResponse(new String(respBytes));
            }
            api.organizer().sendToOrganizer(
                    burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(req, resp));
            searchStatus.setText("Sent to Organizer!");
        } catch (Exception e) {
            info("Error sending to Organizer: " + e.getMessage());
        }
    }

    private void sendToComparer() {
        byte[] data;
        if (editor.getSelectedText() != null) {
            data = editor.getSelectedText().getBytes();
        } else {
            data = editorText().getBytes();
        }
        if (data.length == 0) { info("No content."); return; }
        try {
            api.comparer().sendToComparer(ByteArray.byteArray(data));
            searchStatus.setText("Sent to Comparer!");
        } catch (Exception e) {
            info("Error sending to Comparer: " + e.getMessage());
        }
    }

    /**
     * Inserts a Burp Collaborator payload at the current caret position (or replaces selection).
     */
    private void insertCollaboratorPayload() {
        try {
            var payload = api.collaborator().defaultPayloadGenerator().generatePayload();
            String payloadStr = payload.toString();
            int pos = editor.getCaretPosition();
            String sel = editor.getSelectedText();
            if (sel != null) {
                int start = editor.getSelectionStart();
                int end = editor.getSelectionEnd();
                editor.getDocument().remove(start, end - start);
                editor.getDocument().insertString(start, payloadStr, null);
            } else {
                editor.getDocument().insertString(pos, payloadStr, null);
            }
            modified = true;
            searchStatus.setText("Collaborator payload inserted");
        } catch (Exception e) {
            info("Error generating Collaborator payload: " + e.getMessage());
        }
    }

    /**
     * Renders the response body in the user's default browser.
     * Writes the response body to a temp HTML file and opens it.
     */
    private void openResponseInBrowser() {
        try {
            byte[] raw;
            if (!isRequest && currentContent != null) {
                raw = currentContent;
            } else if (companionContent != null) {
                raw = companionContent;
            } else {
                info("No response available."); return;
            }

            // Find header/body separator in raw bytes
            String fullText = new String(raw);
            int sep = fullText.indexOf("\r\n\r\n");
            int bodyOffset = (sep >= 0) ? sep + 4 : -1;
            if (bodyOffset < 0) {
                sep = fullText.indexOf("\n\n");
                bodyOffset = (sep >= 0) ? sep + 2 : -1;
            }
            if (bodyOffset < 0 || bodyOffset >= raw.length) {
                info("Response body is empty."); return;
            }

            // Extract body as raw bytes (important for binary content)
            byte[] bodyBytes = new byte[raw.length - bodyOffset];
            System.arraycopy(raw, bodyOffset, bodyBytes, 0, bodyBytes.length);
            if (bodyBytes.length == 0) { info("Response body is empty."); return; }

            // Detect Content-Type from headers to pick the right file extension
            String headers = fullText.substring(0, bodyOffset).toLowerCase();
            String ext = ".html"; // default
            if (headers.contains("content-type:")) {
                String ct = headers.substring(headers.indexOf("content-type:") + 13);
                ct = ct.split("\\r?\\n")[0].trim().toLowerCase();
                if (ct.contains("pdf")) ext = ".pdf";
                else if (ct.contains("png")) ext = ".png";
                else if (ct.contains("jpeg") || ct.contains("jpg")) ext = ".jpg";
                else if (ct.contains("gif")) ext = ".gif";
                else if (ct.contains("webp")) ext = ".webp";
                else if (ct.contains("svg")) ext = ".svg";
                else if (ct.contains("json")) ext = ".json";
                else if (ct.contains("xml")) ext = ".xml";
                else if (ct.contains("javascript")) ext = ".js";
                else if (ct.contains("css")) ext = ".css";
                else if (ct.contains("plain")) ext = ".txt";
                else if (ct.contains("octet-stream")) ext = ".bin";
                else if (ct.contains("zip")) ext = ".zip";
                else if (ct.contains("mp4")) ext = ".mp4";
                else if (ct.contains("webm")) ext = ".webm";
                else if (ct.contains("mp3") || ct.contains("mpeg")) ext = ".mp3";
                else if (ct.contains("wav")) ext = ".wav";
                else if (ct.contains("ico")) ext = ".ico";
                else if (ct.contains("bmp")) ext = ".bmp";
                else if (ct.contains("tiff")) ext = ".tiff";
            }

            // Write raw bytes to temp file and open with system default app
            java.io.File tmp = java.io.File.createTempFile("burp_response_", ext);
            tmp.deleteOnExit();
            java.nio.file.Files.write(tmp.toPath(), bodyBytes);

            // For browser-viewable types, use browse(); for others, use open()
            if (ext.equals(".html") || ext.equals(".svg") || ext.equals(".json")
                    || ext.equals(".xml") || ext.equals(".txt") || ext.equals(".pdf")
                    || ext.equals(".js") || ext.equals(".css")) {
                java.awt.Desktop.getDesktop().browse(tmp.toURI());
            } else {
                java.awt.Desktop.getDesktop().open(tmp);
            }
            searchStatus.setText("Opened in browser: " + ext);
        } catch (Exception e) {
            info("Error opening in browser: " + e.getMessage());
        }
    }

    private void copyRequestUrl() {
        HttpRequest req = buildRequestWithVars();
        if (req == null) { info("No request available."); return; }
        try {
            // Construir URL completa: scheme + host + path + query
            String url = req.url();
            // Si la URL ya tiene scheme, está completa
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                // Reconstruir desde headers
                String host = req.headerValue("Host");
                if (host != null) {
                    String scheme = "https://";
                    // Detectar si es HTTP (puerto 80 o explícito)
                    if (host.endsWith(":80")) scheme = "http://";
                    url = scheme + host + url;
                }
            }
            copyToClipboard(url);
            searchStatus.setText("URL copied: " + url);
        } catch (Exception e) {
            info("Error extracting URL: " + e.getMessage());
        }
    }

    // ── Change Request Method / Body Format ──────────────────────────

    /**
     * Changes the HTTP method (e.g. POST→GET, GET→POST, etc.)
     * When changing POST→GET: moves body params to query string.
     * When changing GET→POST: moves query params to body.
     */
    /**
     * Unified method to change request format.
     * - JSON/FORM/XML/MULTIPART: converts body + changes method to POST if needed
     * - GET: moves body params to URL query string + removes body
     * Automatically extracts params from current body (JSON, URL Encoded, XML, Multipart)
     * and converts them to the target format.
     */
    private void changeRequestFormat(String targetFormat) {
        if (!isRequest || lastParsed == null) { info("Only works on requests."); return; }
        try {
            String startLine = lastParsed.startLine();
            String[] slParts = startLine.strip().split("\\s+");
            if (slParts.length < 3) { info("Invalid request line."); return; }

            String oldMethod = slParts[0];
            String path = slParts[1];
            String httpVer = slParts[2];
            String body = lastParsed.rawBody() != null ? lastParsed.rawBody() : "";
            ParsedHttpMessage.BodyType currentType = lastParsed.bodyType();
            List<Map.Entry<String, String>> headers = new ArrayList<>(lastParsed.headers());

            // Collect params from ALL possible sources: body + URL query string
            Map<String, String> params = new LinkedHashMap<>();

            // 1) Parse body params
            Map<String, String> bodyParams = parseBodyParams(body, currentType);
            if (bodyParams != null) params.putAll(bodyParams);

            // 2) Parse URL query params
            int qIdx = path.indexOf('?');
            if (qIdx >= 0) {
                String query = path.substring(qIdx + 1);
                for (String pair : query.split("&")) {
                    int eq = pair.indexOf('=');
                    if (eq > 0) {
                        try {
                            params.putIfAbsent(
                                URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                                URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
                        } catch (Exception ignored) {}
                    }
                }
            }
            // Clean path (remove query for rebuild)
            String cleanPath = qIdx >= 0 ? path.substring(0, qIdx) : path;

            // ── Handle GET: move everything to URL, remove body ──
            if ("GET".equals(targetFormat)) {
                String queryStr = paramsToQueryString(params);
                String newPath = queryStr.isEmpty() ? cleanPath : cleanPath + "?" + queryStr;

                StringBuilder sb = new StringBuilder();
                sb.append("GET ").append(newPath).append(" ").append(httpVer).append("\r\n");
                for (var h : headers) {
                    if (h.getKey().equalsIgnoreCase("Content-Type")
                            || h.getKey().equalsIgnoreCase("Content-Length")) continue;
                    sb.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
                }
                sb.append("\r\n");

                setEditorText(sb.toString());
                searchStatus.setText("→ GET (params moved to URL)");
                return;
            }

            // ── Handle body formats: JSON, FORM, XML, MULTIPART ──
            // Auto-change method to POST if current method doesn't support body
            String newMethod = oldMethod.matches("POST|PUT|PATCH") ? oldMethod : "POST";

            String newBody;
            String newContentType;

            switch (targetFormat) {
                case "JSON" -> {
                    newContentType = "application/json";
                    if (!params.isEmpty()) {
                        StringBuilder sb = new StringBuilder("{\n");
                        int count = 0;
                        for (var entry : params.entrySet()) {
                            if (count > 0) sb.append(",\n");
                            sb.append("  \"").append(escapeJson(entry.getKey())).append("\": \"")
                              .append(escapeJson(entry.getValue())).append("\"");
                            count++;
                        }
                        sb.append("\n}");
                        newBody = sb.toString();
                    } else if (currentType == ParsedHttpMessage.BodyType.JSON) {
                        newBody = body;
                    } else {
                        newBody = "{\n  \n}";
                    }
                }
                case "FORM" -> {
                    newContentType = "application/x-www-form-urlencoded";
                    if (!params.isEmpty()) {
                        newBody = paramsToQueryString(params);
                    } else if (currentType == ParsedHttpMessage.BodyType.FORM) {
                        newBody = body;
                    } else {
                        newBody = "";
                    }
                }
                case "XML" -> {
                    newContentType = "application/xml";
                    if (!params.isEmpty()) {
                        StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<request>\n");
                        for (var entry : params.entrySet()) {
                            String tag = entry.getKey().replaceAll("[^a-zA-Z0-9_-]", "_");
                            sb.append("  <").append(tag).append(">")
                              .append(escapeXml(entry.getValue()))
                              .append("</").append(tag).append(">\n");
                        }
                        sb.append("</request>");
                        newBody = sb.toString();
                    } else if (currentType == ParsedHttpMessage.BodyType.XML) {
                        newBody = body;
                    } else {
                        newBody = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<request>\n  \n</request>";
                    }
                }
                case "MULTIPART" -> {
                    String boundary = "----ProColorBoundary" + System.currentTimeMillis();
                    newContentType = "multipart/form-data; boundary=" + boundary;
                    if (!params.isEmpty()) {
                        StringBuilder sb = new StringBuilder();
                        for (var entry : params.entrySet()) {
                            sb.append("--").append(boundary).append("\r\n");
                            sb.append("Content-Disposition: form-data; name=\"").append(entry.getKey()).append("\"\r\n\r\n");
                            sb.append(entry.getValue()).append("\r\n");
                        }
                        sb.append("--").append(boundary).append("--\r\n");
                        newBody = sb.toString();
                    } else {
                        newBody = "--" + boundary + "\r\n"
                                + "Content-Disposition: form-data; name=\"field\"\r\n\r\n"
                                + "value\r\n"
                                + "--" + boundary + "--\r\n";
                    }
                }
                default -> {
                    newContentType = "text/plain";
                    newBody = body;
                }
            }

            // Rebuild request: new method, clean path (no query), new body
            StringBuilder sb = new StringBuilder();
            sb.append(newMethod).append(" ").append(cleanPath).append(" ").append(httpVer).append("\r\n");

            boolean ctReplaced = false;
            boolean clReplaced = false;
            for (var h : headers) {
                if (h.getKey().equalsIgnoreCase("Content-Type")) {
                    sb.append("Content-Type: ").append(newContentType).append("\r\n");
                    ctReplaced = true;
                } else if (h.getKey().equalsIgnoreCase("Content-Length")) {
                    sb.append("Content-Length: ").append(newBody.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
                    clReplaced = true;
                } else {
                    sb.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
                }
            }
            if (!ctReplaced) sb.append("Content-Type: ").append(newContentType).append("\r\n");
            if (!clReplaced && !newBody.isEmpty()) {
                sb.append("Content-Length: ").append(newBody.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
            }
            sb.append("\r\n").append(newBody);

            setEditorText(sb.toString());
            searchStatus.setText(oldMethod + " → " + newMethod + " | Body → " + targetFormat);
        } catch (Exception e) {
            info("Error changing request format: " + e.getMessage());
        }
    }

    private String paramsToQueryString(Map<String, String> params) {
        if (params == null || params.isEmpty()) return "";
        return params.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }

    private List<String> splitJsonPairs(String json) {
        List<String> result = new ArrayList<>();
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        int start = 0;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escaped) { escaped = false; continue; }
            if (c == '\\') { escaped = true; continue; }
            if (c == '"') { inString = !inString; continue; }
            if (inString) continue;
            if (c == '{' || c == '[') depth++;
            if (c == '}' || c == ']') depth--;
            if (c == ',' && depth == 0) {
                result.add(json.substring(start, i).strip());
                start = i + 1;
            }
        }
        if (start < json.length()) result.add(json.substring(start).strip());
        return result;
    }

    private Map<String, String> parseBodyParams(String body, ParsedHttpMessage.BodyType type) {
        if (body == null || body.isBlank()) return null;
        Map<String, String> params = new LinkedHashMap<>();
        try {
            switch (type) {
                case FORM -> parseFormParams(body, params);
                case JSON -> parseJsonParams(body, params);
                case XML -> parseXmlParams(body, params);
                default -> {
                    // Heuristic: try to detect format from content
                    String t = body.strip();
                    if (t.startsWith("{")) parseJsonParams(body, params);
                    else if (t.contains("Content-Disposition:") && t.contains("--")) parseMultipartParams(body, params);
                    else if (t.startsWith("<")) parseXmlParams(body, params);
                    else if (t.contains("=")) parseFormParams(body, params);
                }
            }
            // Also try multipart even if type says something else
            if (params.isEmpty() && body.contains("Content-Disposition:") && body.contains("--")) {
                parseMultipartParams(body, params);
            }
        } catch (Exception ignored) {}
        return params.isEmpty() ? null : params;
    }

    private static void parseFormParams(String body, Map<String, String> params) {
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                try {
                    params.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                               URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
                } catch (Exception e) {
                    params.put(pair.substring(0, eq), pair.substring(eq + 1));
                }
            }
        }
    }

    private void parseJsonParams(String body, Map<String, String> params) {
        String trimmed = body.strip();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            String inner = trimmed.substring(1, trimmed.length() - 1).strip();
            for (String pair : splitJsonPairs(inner)) {
                int ci = pair.indexOf(':');
                if (ci < 0) continue;
                String key = pair.substring(0, ci).strip();
                String val = pair.substring(ci + 1).strip();
                if (key.startsWith("\"") && key.endsWith("\"")) key = key.substring(1, key.length() - 1);
                if (val.startsWith("\"") && val.endsWith("\"")) val = val.substring(1, val.length() - 1);
                else if (val.equals("null")) val = "";
                params.put(key, val);
            }
        }
    }

    private static void parseXmlParams(String body, Map<String, String> params) {
        Matcher m = PAT_XML_TAG.matcher(body);
        while (m.find()) params.put(m.group(1), m.group(2));
    }

    private static void parseMultipartParams(String body, Map<String, String> params) {
        String[] lines = body.split("\\r?\\n");
        if (lines.length < 2) return;
        String boundary = lines[0].strip();
        if (!boundary.startsWith("--")) return;

        String[] parts = body.split(Pattern.quote(boundary));
        for (String part : parts) {
            if (part.isBlank() || part.strip().equals("--")) continue;
            Matcher nm = PAT_MULTIPART_DISP.matcher(part);
            if (nm.find()) {
                String name = nm.group(1);
                int blankLine = part.indexOf("\n\n");
                if (blankLine < 0) blankLine = part.indexOf("\r\n\r\n");
                if (blankLine >= 0) {
                    String value = part.substring(blankLine).strip();
                    if (value.endsWith("--")) value = value.substring(0, value.length() - 2).strip();
                    params.put(name, value);
                }
            }
        }
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private static String escapeXml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }

    private void setEditorText(String text) {
        updating = true;
        try {
            editor.setText("");
            modified = true;
            // Re-parse and re-render
            lastParsed = HttpMessageParser.parse(text, isRequest);
            renderWithOverlays();
            editor.setCaretPosition(0);
        } finally {
            updating = false;
        }
    }

    // ── Create Issue ────────────────────────────────────────────────

    private void createScanIssue() {
        HttpRequest req = buildRequestWithVars();
        if (req == null) { info("No request available."); return; }
        try {
            // Diálogo para crear issue
            JPanel issuePanel = new JPanel(new GridBagLayout());
            GridBagConstraints gc = new GridBagConstraints();
            gc.insets = new Insets(4, 4, 4, 4);
            gc.fill = GridBagConstraints.HORIZONTAL;
            gc.anchor = GridBagConstraints.WEST;

            gc.gridx = 0; gc.gridy = 0; issuePanel.add(new JLabel("Issue name:"), gc);
            JTextField nameField = new JTextField(30);
            gc.gridx = 1; issuePanel.add(nameField, gc);

            gc.gridx = 0; gc.gridy = 1; issuePanel.add(new JLabel("Severity:"), gc);
            JComboBox<String> sevCombo = new JComboBox<>(new String[]{
                    "High", "Medium", "Low", "Information", "False positive"});
            gc.gridx = 1; issuePanel.add(sevCombo, gc);

            gc.gridx = 0; gc.gridy = 2; issuePanel.add(new JLabel("Confidence:"), gc);
            JComboBox<String> confCombo = new JComboBox<>(new String[]{
                    "Certain", "Firm", "Tentative"});
            gc.gridx = 1; issuePanel.add(confCombo, gc);

            gc.gridx = 0; gc.gridy = 3; issuePanel.add(new JLabel("Detail:"), gc);
            JTextArea detailArea = new JTextArea(5, 30);
            detailArea.setLineWrap(true); detailArea.setWrapStyleWord(true);
            gc.gridx = 1; issuePanel.add(new JScrollPane(detailArea), gc);

            gc.gridx = 0; gc.gridy = 4; issuePanel.add(new JLabel("Remediation:"), gc);
            JTextArea remArea = new JTextArea(3, 30);
            remArea.setLineWrap(true); remArea.setWrapStyleWord(true);
            gc.gridx = 1; issuePanel.add(new JScrollPane(remArea), gc);

            int res = JOptionPane.showConfirmDialog(mainPanel, issuePanel,
                    "Create Issue", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (res != JOptionPane.OK_OPTION) return;
            if (nameField.getText().isBlank()) { info("Issue name is required."); return; }

            String sevStr = (String) sevCombo.getSelectedItem();
            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity severity =
                    switch (sevStr) {
                        case "High" -> burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.HIGH;
                        case "Medium" -> burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.MEDIUM;
                        case "Low" -> burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.LOW;
                        case "False positive" -> burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.FALSE_POSITIVE;
                        default -> burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.INFORMATION;
                    };
            String confStr = (String) confCombo.getSelectedItem();
            burp.api.montoya.scanner.audit.issues.AuditIssueConfidence confidence =
                    switch (confStr) {
                        case "Certain" -> burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.CERTAIN;
                        case "Firm" -> burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.FIRM;
                        default -> burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.TENTATIVE;
                    };

            String host = req.headerValue("Host");
            String baseUrl = "https://" + (host != null ? host : "unknown");

            burp.api.montoya.scanner.audit.issues.AuditIssue issue =
                    burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue(
                            nameField.getText(),
                            detailArea.getText(),
                            remArea.getText(),
                            baseUrl,
                            severity,
                            confidence,
                            null, null,
                            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.INFORMATION,
                            burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(req, null));

            api.siteMap().add(issue);
            searchStatus.setText("Issue created: " + nameField.getText());
        } catch (Exception e) {
            info("Error creating issue: " + e.getMessage());
        }
    }

    // ── Engagement tools ────────────────────────────────────────────

    private static final String[] CSRF_TYPES = {
            "Auto-submit Form (URL-encoded)",
            "Auto-submit Form (multipart/form-data)",
            "XMLHttpRequest (JSON)",
            "XMLHttpRequest (URL-encoded)",
            "Fetch API (JSON)",
            "Fetch API (URL-encoded)",
            "IMG/iframe GET",
            "jQuery AJAX (JSON)",
    };

    private void generateCsrfPoc() {
        byte[] reqBytes = getRequestBytes();
        if (reqBytes == null) { info("No request available."); return; }

        ParsedHttpMessage reqMsg = isRequest ? lastParsed : companionParsed;
        if (reqMsg == null) { info("No parsed request available."); return; }

        // Selector de tipo
        String csrfType = (String) JOptionPane.showInputDialog(mainPanel,
                "Select CSRF PoC type:", "Generate CSRF PoC",
                JOptionPane.PLAIN_MESSAGE, null, CSRF_TYPES, CSRF_TYPES[0]);
        if (csrfType == null) return;

        String method = "GET";
        String path = "/";
        String startLine = reqMsg.startLine();
        if (startLine != null) {
            String[] parts = startLine.strip().split("\\s+");
            if (parts.length >= 2) { method = parts[0]; path = parts[1]; }
        }

        String host = "", contentType = "";
        for (var hdr : reqMsg.headers()) {
            if (hdr.getKey().equalsIgnoreCase("Host")) host = hdr.getValue();
            if (hdr.getKey().equalsIgnoreCase("Content-Type")) contentType = hdr.getValue();
        }
        String fullUrl = "https://" + host + path;
        String body = reqMsg.hasBody() ? reqMsg.rawBody() : "";

        String poc;
        if (csrfType.startsWith("Auto-submit Form (URL")) {
            poc = csrfFormUrlEncoded(fullUrl, method, body);
        } else if (csrfType.startsWith("Auto-submit Form (multi")) {
            poc = csrfFormMultipart(fullUrl, method, body);
        } else if (csrfType.startsWith("XMLHttpRequest (JSON")) {
            poc = csrfXhrJson(fullUrl, method, body);
        } else if (csrfType.startsWith("XMLHttpRequest (URL")) {
            poc = csrfXhrUrlEncoded(fullUrl, method, body);
        } else if (csrfType.startsWith("Fetch API (JSON")) {
            poc = csrfFetchJson(fullUrl, method, body);
        } else if (csrfType.startsWith("Fetch API (URL")) {
            poc = csrfFetchUrlEncoded(fullUrl, method, body);
        } else if (csrfType.startsWith("IMG")) {
            poc = csrfImgIframe(fullUrl);
        } else if (csrfType.startsWith("jQuery")) {
            poc = csrfJqueryAjax(fullUrl, method, body);
        } else {
            poc = csrfFormUrlEncoded(fullUrl, method, body);
        }

        // Apply template variables to the generated PoC
        poc = TemplateVars.apply(poc);
        showFinderDialog("CSRF PoC — " + csrfType, poc, poc, "Copy PoC HTML");
    }

    // ── CSRF PoC generators ─────────────────────────────────────────

    private String csrfFormUrlEncoded(String url, String method, String body) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html>\n<head><title>CSRF PoC</title></head>\n<body>\n");
        sb.append("<h1>CSRF PoC — Auto-submit Form (URL-encoded)</h1>\n");
        sb.append("<form id=\"csrf\" action=\"").append(escapeHtml(url)).append("\" method=\"").append(method).append("\">\n");
        if (!body.isEmpty()) {
            for (String param : body.split("&")) {
                String[] kv = param.split("=", 2);
                String n = urlDec(kv[0]), v = kv.length > 1 ? urlDec(kv[1]) : "";
                sb.append("  <input type=\"hidden\" name=\"").append(escapeHtml(n))
                        .append("\" value=\"").append(escapeHtml(v)).append("\" />\n");
            }
        }
        sb.append("  <input type=\"submit\" value=\"Submit\" />\n</form>\n");
        sb.append("<script>document.getElementById('csrf').submit();</script>\n");
        sb.append("</body>\n</html>");
        return sb.toString();
    }

    private String csrfFormMultipart(String url, String method, String body) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html>\n<head><title>CSRF PoC</title></head>\n<body>\n");
        sb.append("<h1>CSRF PoC — Auto-submit Form (multipart)</h1>\n");
        sb.append("<form id=\"csrf\" action=\"").append(escapeHtml(url))
                .append("\" method=\"").append(method)
                .append("\" enctype=\"multipart/form-data\">\n");
        if (!body.isEmpty()) {
            for (String param : body.split("&")) {
                String[] kv = param.split("=", 2);
                String n = urlDec(kv[0]), v = kv.length > 1 ? urlDec(kv[1]) : "";
                sb.append("  <input type=\"hidden\" name=\"").append(escapeHtml(n))
                        .append("\" value=\"").append(escapeHtml(v)).append("\" />\n");
            }
        }
        sb.append("  <input type=\"submit\" value=\"Submit\" />\n</form>\n");
        sb.append("<script>document.getElementById('csrf').submit();</script>\n");
        sb.append("</body>\n</html>");
        return sb.toString();
    }

    private String csrfXhrJson(String url, String method, String body) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html>\n<head><title>CSRF PoC</title></head>\n<body>\n");
        sb.append("<h1>CSRF PoC — XMLHttpRequest (JSON)</h1>\n");
        sb.append("<script>\n");
        sb.append("  var xhr = new XMLHttpRequest();\n");
        sb.append("  xhr.open('").append(method).append("', '").append(escapeJs(url)).append("', true);\n");
        sb.append("  xhr.setRequestHeader('Content-Type', 'application/json');\n");
        sb.append("  xhr.withCredentials = true;\n");
        if (!body.isEmpty()) {
            sb.append("  xhr.send(").append(escapeJsString(body)).append(");\n");
        } else {
            sb.append("  xhr.send();\n");
        }
        sb.append("</script>\n</body>\n</html>");
        return sb.toString();
    }

    private String csrfXhrUrlEncoded(String url, String method, String body) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html>\n<head><title>CSRF PoC</title></head>\n<body>\n");
        sb.append("<h1>CSRF PoC — XMLHttpRequest (URL-encoded)</h1>\n");
        sb.append("<script>\n");
        sb.append("  var xhr = new XMLHttpRequest();\n");
        sb.append("  xhr.open('").append(method).append("', '").append(escapeJs(url)).append("', true);\n");
        sb.append("  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');\n");
        sb.append("  xhr.withCredentials = true;\n");
        if (!body.isEmpty()) {
            sb.append("  xhr.send(").append(escapeJsString(body)).append(");\n");
        } else {
            sb.append("  xhr.send();\n");
        }
        sb.append("</script>\n</body>\n</html>");
        return sb.toString();
    }

    private String csrfFetchJson(String url, String method, String body) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html>\n<head><title>CSRF PoC</title></head>\n<body>\n");
        sb.append("<h1>CSRF PoC — Fetch API (JSON)</h1>\n");
        sb.append("<script>\n");
        sb.append("  fetch('").append(escapeJs(url)).append("', {\n");
        sb.append("    method: '").append(method).append("',\n");
        sb.append("    credentials: 'include',\n");
        sb.append("    headers: { 'Content-Type': 'application/json' },\n");
        if (!body.isEmpty()) {
            sb.append("    body: ").append(escapeJsString(body)).append("\n");
        }
        sb.append("  });\n");
        sb.append("</script>\n</body>\n</html>");
        return sb.toString();
    }

    private String csrfFetchUrlEncoded(String url, String method, String body) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html>\n<head><title>CSRF PoC</title></head>\n<body>\n");
        sb.append("<h1>CSRF PoC — Fetch API (URL-encoded)</h1>\n");
        sb.append("<script>\n");
        sb.append("  fetch('").append(escapeJs(url)).append("', {\n");
        sb.append("    method: '").append(method).append("',\n");
        sb.append("    credentials: 'include',\n");
        sb.append("    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },\n");
        if (!body.isEmpty()) {
            sb.append("    body: ").append(escapeJsString(body)).append("\n");
        }
        sb.append("  });\n");
        sb.append("</script>\n</body>\n</html>");
        return sb.toString();
    }

    private String csrfImgIframe(String url) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html>\n<head><title>CSRF PoC</title></head>\n<body>\n");
        sb.append("<h1>CSRF PoC — IMG/iframe GET</h1>\n");
        sb.append("<!-- IMG triggers a GET request silently -->\n");
        sb.append("<img src=\"").append(escapeHtml(url)).append("\" style=\"display:none\" />\n\n");
        sb.append("<!-- iframe alternative -->\n");
        sb.append("<iframe src=\"").append(escapeHtml(url)).append("\" style=\"width:0;height:0;border:0;\"></iframe>\n");
        sb.append("</body>\n</html>");
        return sb.toString();
    }

    private String csrfJqueryAjax(String url, String method, String body) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html>\n<head>\n<title>CSRF PoC</title>\n");
        sb.append("<script src=\"https://code.jquery.com/jquery-3.7.1.min.js\"></script>\n");
        sb.append("</head>\n<body>\n");
        sb.append("<h1>CSRF PoC — jQuery AJAX (JSON)</h1>\n");
        sb.append("<script>\n");
        sb.append("  $.ajax({\n");
        sb.append("    url: '").append(escapeJs(url)).append("',\n");
        sb.append("    type: '").append(method).append("',\n");
        sb.append("    contentType: 'application/json',\n");
        sb.append("    xhrFields: { withCredentials: true },\n");
        if (!body.isEmpty()) {
            sb.append("    data: ").append(escapeJsString(body)).append(",\n");
        }
        sb.append("    success: function(r) { console.log('CSRF sent', r); }\n");
        sb.append("  });\n");
        sb.append("</script>\n</body>\n</html>");
        return sb.toString();
    }

    private static String urlDec(String s) {
        try { return java.net.URLDecoder.decode(s, java.nio.charset.StandardCharsets.UTF_8); }
        catch (Exception e) { return s; }
    }

    private static String escapeJs(String s) {
        return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "");
    }

    private static String escapeJsString(String s) {
        // Wrap in quotes, escaping special chars
        return "'" + escapeJs(s) + "'";
    }

    private void findCommentsInResponse() {
        String text = getResponseText();
        if (text == null || text.isEmpty()) { info("No response content."); return; }

        List<String> comments = new ArrayList<>();
        Matcher htmlM = PAT_HTML_COMMENT.matcher(text);
        while (htmlM.find()) comments.add("[HTML] " + htmlM.group().strip());
        Matcher jsM = PAT_JS_SINGLE_COMMENT.matcher(text);
        while (jsM.find()) {
            String c = jsM.group().strip();
            if (!c.startsWith("//http") && !c.startsWith("// http") && c.length() > 4)
                comments.add("[JS] " + c);
        }
        Matcher jsBlockM = PAT_JS_BLOCK_COMMENT.matcher(text);
        while (jsBlockM.find()) comments.add("[JS Block] " + jsBlockM.group().strip());

        if (comments.isEmpty()) {
            searchStatus.setText("No comments found");
            info("No comments found in response.");
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Found ").append(comments.size()).append(" comment(s):\n");
        sb.append("=".repeat(60)).append("\n\n");
        for (String c : comments) sb.append(c).append("\n\n");

        searchStatus.setText(comments.size() + " comment(s) found!");
        showFinderDialog("Find Comments — " + comments.size() + " result(s)",
                sb.toString(), sb.toString(), "Copy All");
    }

    private void findScriptsInResponse() {
        String text = getResponseText();
        if (text == null || text.isEmpty()) { info("No response content."); return; }

        List<String> scripts = new ArrayList<>();
        Matcher srcM = PAT_SCRIPT_SRC.matcher(text);
        while (srcM.find()) scripts.add("[External] " + srcM.group(1));
        Matcher inlineM = PAT_SCRIPT_INLINE.matcher(text);
        while (inlineM.find()) {
            String bd = inlineM.group(1).strip();
            if (!bd.isEmpty()) {
                String preview = bd.length() > 200 ? bd.substring(0, 197) + "..." : bd;
                scripts.add("[Inline] " + preview);
            }
        }
        Matcher jsRef = PAT_JS_FILE_REF.matcher(text);
        Set<String> seenJs = new java.util.LinkedHashSet<>();
        while (jsRef.find()) {
            if (seenJs.add(jsRef.group(1))) scripts.add("[JS File] " + jsRef.group(1));
        }

        if (scripts.isEmpty()) {
            searchStatus.setText("No scripts found");
            info("No scripts found in response.");
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Found ").append(scripts.size()).append(" script reference(s):\n");
        sb.append("=".repeat(60)).append("\n\n");
        for (String s : scripts) sb.append(s).append("\n\n");

        searchStatus.setText(scripts.size() + " script(s) found!");
        showFinderDialog("Find Scripts — " + scripts.size() + " result(s)",
                sb.toString(), sb.toString(), "Copy All");
    }

    private void findFormsInResponse() {
        String text = getResponseText();
        if (text == null || text.isEmpty()) { info("No response content."); return; }

        List<String> forms = new ArrayList<>();
        Matcher formM = PAT_FORM_TAG.matcher(text);
        int idx = 0;
        while (formM.find()) {
            idx++;
            StringBuilder fb = new StringBuilder();
            fb.append("Form #").append(idx);
            String formAttrs = formM.group(1);
            // Extract action and method from <form> attributes
            Matcher attrM = PAT_ATTR.matcher(formAttrs);
            while (attrM.find()) {
                String attrName = attrM.group(1).toLowerCase();
                if ("action".equals(attrName) || "method".equals(attrName)) {
                    fb.append("  ").append(attrName).append("=\"").append(attrM.group(2)).append("\"");
                }
            }
            fb.append("\n");
            // Extract inputs from form body
            String formBody = formM.group(2);
            Matcher inputM = PAT_INPUT_TAG.matcher(formBody);
            while (inputM.find()) {
                String iAttrs = inputM.group(1);
                String type = extractAttr(iAttrs, "type");
                String name = extractAttr(iAttrs, "name");
                String value = extractAttr(iAttrs, "value");
                fb.append("  ").append(type != null ? type : "text");
                if (name != null) fb.append("  name=\"").append(name).append("\"");
                if (value != null) fb.append("  value=\"").append(value).append("\"");
                fb.append("\n");
            }
            forms.add(fb.toString());
        }

        if (forms.isEmpty()) {
            searchStatus.setText("No forms found");
            info("No forms found in response.");
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Found ").append(forms.size()).append(" form(s):\n");
        sb.append("=".repeat(60)).append("\n\n");
        for (String f : forms) sb.append(f).append("\n");

        searchStatus.setText(forms.size() + " form(s) found!");
        showFinderDialog("Find Forms — " + forms.size() + " result(s)",
                sb.toString(), sb.toString(), "Copy All");
    }

    /** Obtiene texto del response (sea de este editor o del companion). */
    private String getResponseText() {
        if (!isRequest) return editorText();
        if (companionContent != null) return new String(companionContent);
        return null;
    }

    private static String extractAttr(String attrs, String name) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "(?i)" + name + "\\s*=\\s*['\"]([^'\"]*)['\"]").matcher(attrs);
        return m.find() ? m.group(1) : null;
    }

    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }

    // ── Utility actions ─────────────────────────────────────────────

    private void copyAsCurl() {
        if (lastParsed == null) { info("No content."); return; }
        if (!lastParsed.isRequest()) { info("Solo disponible para requests."); return; }
        // Apply template variables to the cURL output
        String curl = CurlExporter.toCurl(lastParsed);
        copyToClipboard(TemplateVars.apply(curl));
        searchStatus.setText("cURL copiado!");
    }
    private void decodeJwt() {
        String text = editorText();
        if (text.isEmpty()) { info("No content."); return; }
        showDialog("JWT Decoder", JwtDecoder.findAndDecode(text));
    }
    private void exportToFile() {
        String text = editorText();
        if (text.isEmpty()) { info("No content."); return; }
        String ext = ".txt", name = "http-message";
        if (lastParsed != null) {
            switch (lastParsed.bodyType()) {
                case JSON -> { ext = ".json"; name = "response"; }
                case XML  -> { ext = ".xml"; name = "response"; }
                case HTML -> { ext = ".html"; name = "response"; }
                default -> {}
            }
            if (lastParsed.isRequest()) name = "request";
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File(name + ext));
        if (fc.showSaveDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            try (FileWriter fw = new FileWriter(fc.getSelectedFile())) {
                fw.write(text);
                searchStatus.setText("Exportado: " + fc.getSelectedFile().getName());
            } catch (Exception e) { info("Error: " + e.getMessage()); }
        }
    }

    // ── Snap (screenshot window) ───────────────────────────────────────

    /** Tamaños preset para capturas en px: nombre → {ancho, alto} */
    // Snap saved defaults (persist during session)
    private static String snapDefaultSize = null;   // null = not yet configured
    private static Boolean snapDefaultHorizontal = null;

    private static final String[][] SNAP_SIZES = {
            {"A4 Horizontal (1123x794)",  "1123", "794"},
            {"A4 Vertical (794x1123)",    "794",  "1123"},
            {"Full HD Horizontal (1920x1080)", "1920", "1080"},
            {"Full HD Vertical (1080x1920)",   "1080", "1920"},
            {"HD (1280x720)",             "1280", "720"},
            {"Square (1080x1080)",        "1080", "1080"},
            {"Slide 16:9 (1280x720)",     "1280", "720"},
            {"Slide 4:3 (1024x768)",      "1024", "768"},
    };

    /** Opens Snap config dialog to change saved defaults */
    private void openSnapConfig() {
        String[] sizeOptions = new String[SNAP_SIZES.length];
        for (int i = 0; i < SNAP_SIZES.length; i++) sizeOptions[i] = SNAP_SIZES[i][0];
        String[] layouts = {"Horizontal (lado a lado)", "Vertical (arriba/abajo)"};

        JComboBox<String> sizeCombo = new JComboBox<>(sizeOptions);
        JComboBox<String> layoutCombo = new JComboBox<>(layouts);
        // Pre-select current defaults
        if (snapDefaultSize != null) sizeCombo.setSelectedItem(snapDefaultSize);
        if (snapDefaultHorizontal != null && !snapDefaultHorizontal) layoutCombo.setSelectedIndex(1);

        JPanel optPanel = new JPanel(new GridLayout(2, 2, 8, 4));
        optPanel.add(new JLabel("Tamaño:"));
        optPanel.add(sizeCombo);
        optPanel.add(new JLabel("Layout:"));
        optPanel.add(layoutCombo);

        int result = JOptionPane.showConfirmDialog(mainPanel, optPanel,
                "Snap — Default Configuration", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return;

        snapDefaultSize = (String) sizeCombo.getSelectedItem();
        snapDefaultHorizontal = layoutCombo.getSelectedIndex() == 0;
        searchStatus.setText("Snap defaults saved: " + snapDefaultSize
                + " | " + (snapDefaultHorizontal ? "Horizontal" : "Vertical"));
    }

    private void openSnapWindow() {
        String text = editorText();
        if (text.isEmpty()) { info("No content."); return; }

        String[] sizeOptions = new String[SNAP_SIZES.length];
        for (int i = 0; i < SNAP_SIZES.length; i++) sizeOptions[i] = SNAP_SIZES[i][0];

        // If no defaults saved yet, show config dialog first time
        if (snapDefaultSize == null) {
            String[] layouts = {"Horizontal (lado a lado)", "Vertical (arriba/abajo)"};
            JComboBox<String> sizeCombo = new JComboBox<>(sizeOptions);
            JComboBox<String> layoutCombo = new JComboBox<>(layouts);
            JPanel optPanel = new JPanel(new GridLayout(2, 2, 8, 4));
            optPanel.add(new JLabel("Tamaño:"));
            optPanel.add(sizeCombo);
            optPanel.add(new JLabel("Layout:"));
            optPanel.add(layoutCombo);

            int result = JOptionPane.showConfirmDialog(mainPanel, optPanel,
                    "Snap — Select Default Config (only asked once)", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (result != JOptionPane.OK_OPTION) return;

            snapDefaultSize = (String) sizeCombo.getSelectedItem();
            snapDefaultHorizontal = layoutCombo.getSelectedIndex() == 0;
        }

        String chosen = snapDefaultSize;
        boolean horizontal = snapDefaultHorizontal;

        int w = 1123, h = 794;
        for (String[] sz : SNAP_SIZES) {
            if (sz[0].equals(chosen)) {
                w = Integer.parseInt(sz[1]);
                h = Integer.parseInt(sz[2]);
                break;
            }
        }

        // Determinar cuál es request y cuál response
        ParsedHttpMessage requestParsed, responseParsed;
        String requestText, responseText;

        if (isRequest) {
            requestParsed = lastParsed;
            requestText = text;
            responseParsed = companionParsed;
            responseText = (companionContent != null) ? new String(companionContent) : null;
        } else {
            responseParsed = lastParsed;
            responseText = text;
            requestParsed = companionParsed;
            requestText = (companionContent != null) ? new String(companionContent) : null;
        }

        // Crear ventana
        JFrame snapFrame = new JFrame("Pro Color View — Snap (" + w + "x" + h + ")");
        snapFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        // Build snap panes (no overlays yet)
        SnapPaneRef reqRef = createSnapPane(requestParsed, requestText, "REQUEST");
        SnapPaneRef resRef = createSnapPane(responseParsed, responseText, "RESPONSE");
        JScrollPane reqScroll = wrapSnapPane(reqRef.pane);
        JScrollPane resScroll = wrapSnapPane(resRef.pane);

        // Extraer endpoint del request para el label
        String endpoint = "";
        if (requestParsed != null && requestParsed.startLine() != null) {
            String sl = requestParsed.startLine().strip();
            String[] parts = sl.split("\\s+");
            if (parts.length >= 2) {
                endpoint = parts[0] + " " + parts[1];
            } else {
                endpoint = sl;
            }
        }

        // Labels de sección
        JPanel reqPanel = wrapWithLabel("REQUEST", endpoint, reqScroll);
        JPanel resPanel = wrapWithLabel("RESPONSE", null, resScroll);

        // SplitPane — minimum sizes so divider can move both directions freely
        reqPanel.setMinimumSize(new Dimension(50, 50));
        resPanel.setMinimumSize(new Dimension(50, 50));
        JSplitPane split = new JSplitPane(
                horizontal ? JSplitPane.HORIZONTAL_SPLIT : JSplitPane.VERTICAL_SPLIT,
                reqPanel, resPanel);
        split.setResizeWeight(0.5);
        split.setDividerSize(6);
        split.setContinuousLayout(true);
        split.setBackground(theme.bg);
        split.setBorder(BorderFactory.createEmptyBorder());

        // ── Snap toolbar with HL/Blur fields (responsive wrap) ──
        JPanel snapToolbar = new JPanel(new WrapLayout(FlowLayout.LEFT, 4, 2));
        snapToolbar.setBackground(theme.bg);
        snapToolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0,
                theme.isDark() ? new Color(60, 60, 60) : new Color(200, 200, 200)));

        JLabel snapHlL = new JLabel("HL:");
        snapHlL.setForeground(new Color(255, 214, 102));
        snapHlL.setFont(theme.editorFont.deriveFont(10f));
        JTextField snapHlField = new JTextField(18);
        snapHlField.setFont(theme.editorFont.deriveFont(11f));
        snapHlField.setBackground(theme.searchFieldBg);
        snapHlField.setForeground(theme.fg);
        snapHlField.setCaretColor(theme.caret);
        snapHlField.setToolTipText("Highlight words (comma-separated) — applies to both panes");
        // Pre-populate from current editor
        snapHlField.setText(highlightField != null ? highlightField.getText() : "");

        JLabel snapBlurL = new JLabel("Blur:");
        snapBlurL.setForeground(new Color(180, 180, 210));
        snapBlurL.setFont(theme.editorFont.deriveFont(10f));
        JTextField snapBlurField = new JTextField(18);
        snapBlurField.setFont(theme.editorFont.deriveFont(11f));
        snapBlurField.setBackground(theme.searchFieldBg);
        snapBlurField.setForeground(theme.fg);
        snapBlurField.setCaretColor(theme.caret);
        snapBlurField.setToolTipText("Blur/redact words (comma-separated) — applies to both panes");
        snapBlurField.setText(blurField != null ? blurField.getText() : "");

        JButton snapApplyBtn = new JButton("Apply");
        snapApplyBtn.setFont(theme.editorFont.deriveFont(10f));
        snapApplyBtn.setBackground(theme.searchFieldBg);
        snapApplyBtn.setForeground(theme.fg);
        snapApplyBtn.setFocusPainted(false);
        snapApplyBtn.setMargin(new Insets(2, 8, 2, 8));

        // Apply action: re-render overlays on both panes
        Runnable applySnapOverlaysAction = () -> {
            String hl = snapHlField.getText();
            String blur = snapBlurField.getText();
            applySnapOverlays(reqRef, hl, blur);
            applySnapOverlays(resRef, hl, blur);
        };
        snapApplyBtn.addActionListener(e -> applySnapOverlaysAction.run());
        snapHlField.addActionListener(e -> applySnapOverlaysAction.run());
        snapBlurField.addActionListener(e -> applySnapOverlaysAction.run());

        snapToolbar.add(snapHlL);
        snapToolbar.add(snapHlField);
        snapToolbar.add(snapBlurL);
        snapToolbar.add(snapBlurField);
        snapToolbar.add(snapApplyBtn);

        // ── Annotation toolbar (draw tools) ──
        JSeparator annoSep = new JSeparator(SwingConstants.VERTICAL);
        annoSep.setPreferredSize(new Dimension(1, 18));
        annoSep.setForeground(theme.bodyHint);
        snapToolbar.add(annoSep);

        AnnotationPanel annotationOverlay = new AnnotationPanel();

        JButton rectBtn = new JButton("\u25AD Rect");
        rectBtn.setFont(theme.editorFont.deriveFont(10f));
        rectBtn.setBackground(theme.searchFieldBg);
        rectBtn.setForeground(theme.fg);
        rectBtn.setFocusPainted(false);
        rectBtn.setMargin(new Insets(2, 6, 2, 6));
        rectBtn.setToolTipText("Draw rectangle annotation");

        JButton arrowBtn = new JButton("\u2192 Arrow");
        arrowBtn.setFont(theme.editorFont.deriveFont(10f));
        arrowBtn.setBackground(theme.searchFieldBg);
        arrowBtn.setForeground(theme.fg);
        arrowBtn.setFocusPainted(false);
        arrowBtn.setMargin(new Insets(2, 6, 2, 6));
        arrowBtn.setToolTipText("Draw arrow annotation");

        JButton undoAnnoBtn = new JButton("Undo");
        undoAnnoBtn.setFont(theme.editorFont.deriveFont(10f));
        undoAnnoBtn.setBackground(theme.searchFieldBg);
        undoAnnoBtn.setForeground(theme.fg);
        undoAnnoBtn.setFocusPainted(false);
        undoAnnoBtn.setMargin(new Insets(2, 6, 2, 6));
        undoAnnoBtn.setToolTipText("Undo last annotation (Ctrl+Z)");

        JButton clearAnnoBtn = new JButton("Clear");
        clearAnnoBtn.setFont(theme.editorFont.deriveFont(10f));
        clearAnnoBtn.setBackground(theme.searchFieldBg);
        clearAnnoBtn.setForeground(theme.fg);
        clearAnnoBtn.setFocusPainted(false);
        clearAnnoBtn.setMargin(new Insets(2, 6, 2, 6));
        clearAnnoBtn.setToolTipText("Clear all annotations");

        // Color picker button
        JButton colorAnnoBtn = new JButton("\u25CF");
        colorAnnoBtn.setFont(theme.editorFont.deriveFont(12f));
        colorAnnoBtn.setForeground(annotationOverlay.getAnnotationColor());
        colorAnnoBtn.setBackground(theme.searchFieldBg);
        colorAnnoBtn.setFocusPainted(false);
        colorAnnoBtn.setMargin(new Insets(2, 6, 2, 6));
        colorAnnoBtn.setToolTipText("Change annotation color");

        // Active tool highlight
        Runnable updateToolButtons = () -> {
            AnnotationPanel.Tool tool = annotationOverlay.getTool();
            Color activeBg = theme.isDark() ? new Color(60, 80, 110) : new Color(180, 210, 240);
            rectBtn.setBackground(tool == AnnotationPanel.Tool.RECT ? activeBg : theme.searchFieldBg);
            arrowBtn.setBackground(tool == AnnotationPanel.Tool.ARROW ? activeBg : theme.searchFieldBg);
        };

        rectBtn.addActionListener(e -> {
            annotationOverlay.setTool(
                    annotationOverlay.getTool() == AnnotationPanel.Tool.RECT
                            ? AnnotationPanel.Tool.NONE : AnnotationPanel.Tool.RECT);
            updateToolButtons.run();
        });
        arrowBtn.addActionListener(e -> {
            annotationOverlay.setTool(
                    annotationOverlay.getTool() == AnnotationPanel.Tool.ARROW
                            ? AnnotationPanel.Tool.NONE : AnnotationPanel.Tool.ARROW);
            updateToolButtons.run();
        });
        undoAnnoBtn.addActionListener(e -> annotationOverlay.undoLast());
        clearAnnoBtn.addActionListener(e -> annotationOverlay.clearAll());
        colorAnnoBtn.addActionListener(e -> {
            Color picked = JColorChooser.showDialog(snapFrame, "Annotation Color",
                    annotationOverlay.getAnnotationColor());
            if (picked != null) {
                annotationOverlay.setAnnotationColor(picked);
                colorAnnoBtn.setForeground(picked);
            }
        });

        snapToolbar.add(rectBtn);
        snapToolbar.add(arrowBtn);
        snapToolbar.add(colorAnnoBtn);
        snapToolbar.add(undoAnnoBtn);
        snapToolbar.add(clearAnnoBtn);

        JSeparator saveSep = new JSeparator(SwingConstants.VERTICAL);
        saveSep.setPreferredSize(new Dimension(1, 18));
        saveSep.setForeground(theme.bodyHint);
        snapToolbar.add(saveSep);

        JButton saveImageBtn = new JButton("\uD83D\uDCF7 Save Image");
        saveImageBtn.setFont(theme.editorFont.deriveFont(10f));
        saveImageBtn.setBackground(theme.searchFieldBg);
        saveImageBtn.setForeground(theme.isDark() ? new Color(94, 234, 212) : new Color(22, 128, 96));
        saveImageBtn.setFocusPainted(false);
        saveImageBtn.setMargin(new Insets(2, 8, 2, 8));
        saveImageBtn.setToolTipText("Save screenshot as PNG image (with annotations)");
        snapToolbar.add(saveImageBtn);

        JButton clipImageBtn = new JButton("\uD83D\uDCCB Clipboard");
        clipImageBtn.setFont(theme.editorFont.deriveFont(10f));
        clipImageBtn.setBackground(theme.searchFieldBg);
        clipImageBtn.setForeground(theme.isDark() ? new Color(124, 211, 255) : new Color(0, 105, 170));
        clipImageBtn.setFocusPainted(false);
        clipImageBtn.setMargin(new Insets(2, 8, 2, 8));
        clipImageBtn.setToolTipText("Copy screenshot to clipboard (with annotations)");
        snapToolbar.add(clipImageBtn);

        // ── Status bar ──
        JPanel snapStatus = new JPanel(new BorderLayout());
        snapStatus.setBackground(theme.bg);
        JLabel snapInfo = new JLabel("  " + chosen + "  |  Pro Color View");
        snapInfo.setForeground(theme.bodyHint);
        snapInfo.setFont(theme.editorFont.deriveFont(10f));
        snapStatus.add(snapInfo, BorderLayout.WEST);

        final JFrame frameRef = snapFrame;

        JButton resizeBtn = new JButton("Resize");
        resizeBtn.setFont(theme.editorFont.deriveFont(10f));
        resizeBtn.setBackground(theme.bg);
        resizeBtn.setForeground(theme.bodyHint);
        resizeBtn.setBorderPainted(false);
        resizeBtn.setFocusPainted(false);
        resizeBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        resizeBtn.addActionListener(e -> {
            String newSize = (String) JOptionPane.showInputDialog(frameRef,
                    "Nuevo tamaño:", "Resize",
                    JOptionPane.PLAIN_MESSAGE, null, sizeOptions, sizeOptions[0]);
            if (newSize != null) {
                for (String[] sz : SNAP_SIZES) {
                    if (sz[0].equals(newSize)) {
                        int nw = Integer.parseInt(sz[1]);
                        int nh = Integer.parseInt(sz[2]);
                        frameRef.setSize(nw, nh);
                        snapInfo.setText("  " + newSize + "  |  Pro Color View");
                        frameRef.setTitle("Pro Color View — Snap (" + nw + "x" + nh + ")");
                        break;
                    }
                }
            }
        });

        JButton flipBtn = new JButton("Flip");
        flipBtn.setFont(theme.editorFont.deriveFont(10f));
        flipBtn.setBackground(theme.bg);
        flipBtn.setForeground(theme.bodyHint);
        flipBtn.setBorderPainted(false);
        flipBtn.setFocusPainted(false);
        flipBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        flipBtn.setToolTipText("Cambiar orientación horizontal/vertical");
        flipBtn.addActionListener(e -> {
            int orient = split.getOrientation();
            split.setOrientation(orient == JSplitPane.HORIZONTAL_SPLIT
                    ? JSplitPane.VERTICAL_SPLIT : JSplitPane.HORIZONTAL_SPLIT);
            split.setResizeWeight(0.5);
            split.resetToPreferredSizes();
        });

        JButton configBtn = new JButton("Config");
        configBtn.setFont(theme.editorFont.deriveFont(10f));
        configBtn.setBackground(theme.bg);
        configBtn.setForeground(theme.bodyHint);
        configBtn.setBorderPainted(false);
        configBtn.setFocusPainted(false);
        configBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        configBtn.setToolTipText("Change default Snap size and layout");
        configBtn.addActionListener(e -> {
            openSnapConfig();
            // Apply new config to current window
            if (snapDefaultSize != null) {
                for (String[] sz : SNAP_SIZES) {
                    if (sz[0].equals(snapDefaultSize)) {
                        int nw = Integer.parseInt(sz[1]);
                        int nh = Integer.parseInt(sz[2]);
                        frameRef.setSize(nw, nh);
                        snapInfo.setText("  " + snapDefaultSize + "  |  Pro Color View");
                        frameRef.setTitle("Pro Color View — Snap (" + nw + "x" + nh + ")");
                        break;
                    }
                }
                split.setOrientation(snapDefaultHorizontal
                        ? JSplitPane.HORIZONTAL_SPLIT : JSplitPane.VERTICAL_SPLIT);
                split.setResizeWeight(0.5);
                SwingUtilities.invokeLater(() -> split.setDividerLocation(0.5));
            }
        });

        JPanel rightBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        rightBar.setBackground(theme.bg);
        rightBar.add(configBtn);
        rightBar.add(flipBtn);
        rightBar.add(resizeBtn);
        snapStatus.add(rightBar, BorderLayout.EAST);

        // ── Assemble frame ──
        JPanel topBar = new JPanel(new BorderLayout());
        topBar.add(snapToolbar, BorderLayout.CENTER);

        // ── Layered pane: split + annotation overlay ──
        JLayeredPane layeredPane = new JLayeredPane();
        layeredPane.setLayout(null); // manual layout to stack components
        layeredPane.add(split, JLayeredPane.DEFAULT_LAYER);
        layeredPane.add(annotationOverlay, JLayeredPane.PALETTE_LAYER);

        // Keep both layers sized to match the layered pane
        JPanel centerWrapper = new JPanel(new BorderLayout()) {
            @Override
            public void doLayout() {
                super.doLayout();
                Dimension sz = layeredPane.getSize();
                split.setBounds(0, 0, sz.width, sz.height);
                annotationOverlay.setBounds(0, 0, sz.width, sz.height);
            }
        };
        centerWrapper.add(layeredPane, BorderLayout.CENTER);
        // Forward resize events
        layeredPane.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                Dimension sz = layeredPane.getSize();
                split.setBounds(0, 0, sz.width, sz.height);
                annotationOverlay.setBounds(0, 0, sz.width, sz.height);
            }
        });

        // Save Image action — captures the layered pane (split + annotations) as PNG
        saveImageBtn.addActionListener(e -> {
            // Temporarily deselect drawing tool so crosshair doesn't show
            AnnotationPanel.Tool prevTool = annotationOverlay.getTool();
            annotationOverlay.setTool(AnnotationPanel.Tool.NONE);
            updateToolButtons.run();

            try {
                // Capture the content area (split + annotation overlay)
                int cw = layeredPane.getWidth();
                int ch = layeredPane.getHeight();
                if (cw <= 0 || ch <= 0) { info("Nothing to capture."); return; }

                java.awt.image.BufferedImage img = new java.awt.image.BufferedImage(
                        cw, ch, java.awt.image.BufferedImage.TYPE_INT_ARGB);
                Graphics2D g2 = img.createGraphics();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);

                // Paint split pane first
                split.paint(g2);
                // Paint annotations on top
                annotationOverlay.paint(g2);
                g2.dispose();

                // File chooser
                JFileChooser fc = new JFileChooser();
                fc.setDialogTitle("Save Snap Image");
                fc.setSelectedFile(new File("snap-screenshot.png"));
                fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("PNG Image", "png"));
                if (fc.showSaveDialog(frameRef) == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    if (!file.getName().toLowerCase().endsWith(".png")) {
                        file = new File(file.getAbsolutePath() + ".png");
                    }
                    javax.imageio.ImageIO.write(img, "PNG", file);
                    snapInfo.setText("  Saved: " + file.getName() + "  |  Pro Color View");
                }
            } catch (Exception ex) {
                info("Error saving image: " + ex.getMessage());
            } finally {
                // Restore previous tool
                annotationOverlay.setTool(prevTool);
                updateToolButtons.run();
            }
        });

        // Clipboard action — copies snap image to system clipboard
        clipImageBtn.addActionListener(e -> {
            AnnotationPanel.Tool prevTool = annotationOverlay.getTool();
            annotationOverlay.setTool(AnnotationPanel.Tool.NONE);
            updateToolButtons.run();
            try {
                int cw2 = layeredPane.getWidth();
                int ch2 = layeredPane.getHeight();
                if (cw2 <= 0 || ch2 <= 0) { info("Nothing to capture."); return; }

                java.awt.image.BufferedImage img = new java.awt.image.BufferedImage(
                        cw2, ch2, java.awt.image.BufferedImage.TYPE_INT_ARGB);
                Graphics2D g2 = img.createGraphics();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
                split.paint(g2);
                annotationOverlay.paint(g2);
                g2.dispose();

                // Copy to clipboard using Transferable
                java.awt.datatransfer.Transferable transferable = new java.awt.datatransfer.Transferable() {
                    @Override
                    public java.awt.datatransfer.DataFlavor[] getTransferDataFlavors() {
                        return new java.awt.datatransfer.DataFlavor[]{java.awt.datatransfer.DataFlavor.imageFlavor};
                    }
                    @Override
                    public boolean isDataFlavorSupported(java.awt.datatransfer.DataFlavor flavor) {
                        return java.awt.datatransfer.DataFlavor.imageFlavor.equals(flavor);
                    }
                    @Override
                    public Object getTransferData(java.awt.datatransfer.DataFlavor flavor) {
                        return img;
                    }
                };
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(transferable, null);
                snapInfo.setText("  Copied to clipboard!  |  Pro Color View");
            } catch (Exception ex) {
                info("Error copying to clipboard: " + ex.getMessage());
            } finally {
                annotationOverlay.setTool(prevTool);
                updateToolButtons.run();
            }
        });

        snapFrame.getContentPane().setBackground(theme.bg);
        snapFrame.add(topBar, BorderLayout.NORTH);
        snapFrame.add(centerWrapper, BorderLayout.CENTER);
        snapFrame.add(snapStatus, BorderLayout.SOUTH);
        snapFrame.setSize(w, h);
        snapFrame.setLocationRelativeTo(null);

        // ── Snap keyboard shortcuts ──
        JRootPane snapRoot = snapFrame.getRootPane();
        InputMap snapIm = snapRoot.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        ActionMap snapAm = snapRoot.getActionMap();
        // R = toggle Rectangle tool
        snapIm.put(KeyStroke.getKeyStroke(KeyEvent.VK_R, 0), "snapRect");
        snapAm.put("snapRect", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent ev) {
                rectBtn.doClick();
            }
        });
        // A = toggle Arrow tool
        snapIm.put(KeyStroke.getKeyStroke(KeyEvent.VK_A, 0), "snapArrow");
        snapAm.put("snapArrow", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent ev) {
                arrowBtn.doClick();
            }
        });
        // Escape = deselect tool
        snapIm.put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "snapEscTool");
        snapAm.put("snapEscTool", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent ev) {
                annotationOverlay.setTool(AnnotationPanel.Tool.NONE);
                updateToolButtons.run();
            }
        });
        // Ctrl+Shift+C / Cmd+Shift+C = copy screenshot to clipboard
        snapIm.put(KeyStroke.getKeyStroke(KeyEvent.VK_C, MOD | InputEvent.SHIFT_DOWN_MASK), "snapClipboard");
        snapAm.put("snapClipboard", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent ev) {
                clipImageBtn.doClick();
            }
        });

        // Apply initial overlays from current editor fields, then show
        applySnapOverlaysAction.run();
        snapFrame.setVisible(true);

        SwingUtilities.invokeLater(() -> split.setDividerLocation(0.5));

        searchStatus.setText("Snap window opened (" + w + "x" + h + ")");
    }

    /**
     * Crea un JScrollPane con un WrapTextPane colorizado para la ventana Snap.
     */
    /**
     * Record to hold references to a snap pane for re-rendering overlays.
     */
    /** Mutable holder for snap pane state — allows updating parsed content after minimize */
    private static class SnapPaneRef {
        final WrapTextPane pane;
        ParsedHttpMessage parsed;
        String rawText;
        SnapPaneRef(WrapTextPane pane, ParsedHttpMessage parsed, String rawText) {
            this.pane = pane; this.parsed = parsed; this.rawText = rawText;
        }
    }

    private SnapPaneRef createSnapPane(ParsedHttpMessage parsed, String rawText, String fallbackLabel) {
        WrapTextPane pane = new WrapTextPane();
        pane.setEditable(false);
        pane.setBackground(theme.bg);
        pane.setForeground(theme.fg);
        pane.setCaretColor(theme.caret);
        pane.setFont(theme.editorFont);
        pane.setEditorKit(new WrapEditorKit());

        // Render content (colorized or plain text) — overlays applied separately
        if (parsed != null) {
            try {
                HttpColorizer.render(pane.getStyledDocument(), parsed, theme, prettyMode);
            } catch (Exception ex) {
                pane.setText(rawText != null ? rawText : "(no " + fallbackLabel.toLowerCase() + " available)");
            }
        } else if (rawText != null) {
            pane.setText(rawText);
        } else {
            pane.setText("(no " + fallbackLabel.toLowerCase() + " available)");
        }
        pane.setCaretPosition(0);
        return new SnapPaneRef(pane, parsed, rawText);
    }

    private JScrollPane wrapSnapPane(WrapTextPane pane) {
        LineNumberGutter gutter = new LineNumberGutter(pane, theme.editorFont, theme.bodyHint, theme.bg);
        pane.getDocument().addDocumentListener(gutter);
        JScrollPane sp = new JScrollPane(pane);
        sp.setRowHeaderView(gutter);
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.getViewport().setBackground(theme.bg);
        return sp;
    }

    /** Apply HL/Blur overlays to a snap pane. Re-renders from scratch to clear old overlays. */
    private void applySnapOverlays(SnapPaneRef ref, String hlWords, String blurWords) {
        WrapTextPane pane = ref.pane;
        // Re-render base content first (clears old overlays)
        if (ref.parsed != null) {
            try {
                HttpColorizer.render(pane.getStyledDocument(), ref.parsed, theme, prettyMode);
            } catch (Exception ex) {
                pane.setText(ref.rawText != null ? ref.rawText : "");
            }
        }
        // Now apply overlays
        try {
            if (hlWords != null && !hlWords.isBlank()) {
                OverlayManager.applyHighlights(pane.getStyledDocument(), hlWords, theme);
            }
            if (blurWords != null && !blurWords.isBlank()) {
                OverlayManager.applyBlur(pane.getStyledDocument(), blurWords, theme);
            }
        } catch (Exception ignored) {}
    }

    /** Headers that are generally less important for pentest screenshots */
    // ── Request header classification ──
    private static final Set<String> NOISE_HEADERS_REQ = Set.of(
            "accept", "accept-language", "accept-encoding",
            "cache-control", "pragma", "connection", "keep-alive",
            "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode",
            "sec-fetch-site", "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile",
            "sec-ch-ua-platform", "sec-ch-ua-full-version-list",
            "sec-gpc", "dnt", "te", "priority",
            "if-none-match", "if-modified-since",
            "x-requested-with"
    );
    private static final Set<String> ESSENTIAL_HEADERS_REQ = Set.of(
            "host", "content-type", "content-length", "authorization",
            "cookie", "origin", "referer", "user-agent",
            "x-csrf-token", "x-xsrf-token", "x-forwarded-for",
            "x-api-key", "api-key", "bearer", "token"
    );

    // ── Response header classification ──
    private static final Set<String> NOISE_HEADERS_RES = Set.of(
            "date", "server", "x-powered-by", "via", "vary",
            "cache-control", "pragma", "expires", "etag",
            "last-modified", "age", "connection", "keep-alive",
            "transfer-encoding", "accept-ranges", "x-request-id",
            "x-runtime", "x-frame-options", "x-content-type-options",
            "x-xss-protection", "strict-transport-security",
            "referrer-policy", "permissions-policy",
            "content-security-policy-report-only",
            "nel", "report-to", "expect-ct",
            "alt-svc", "cf-ray", "cf-cache-status"
    );
    private static final Set<String> ESSENTIAL_HEADERS_RES = Set.of(
            "content-type", "content-length", "set-cookie",
            "location", "www-authenticate", "authorization",
            "access-control-allow-origin", "access-control-allow-credentials",
            "access-control-allow-methods", "access-control-allow-headers",
            "content-disposition", "x-csrf-token", "x-xsrf-token",
            "content-security-policy"
    );

    /**
     * Minimize Headers: lets user toggle which headers are visible.
     * Hidden headers are stored and can be restored by running minimize again.
     * Works on both requests and responses. Also shows companion headers (response)
     * when available, so both can be minimized/restored in one dialog.
     */
    private void minimizeHeaders() {
        if (lastParsed == null) { info("No content to minimize."); return; }

        boolean forRequest = lastParsed.isRequest();
        Set<String> noiseSet = forRequest ? NOISE_HEADERS_REQ : NOISE_HEADERS_RES;
        Set<String> essentialSet = forRequest ? ESSENTIAL_HEADERS_REQ : ESSENTIAL_HEADERS_RES;
        String label = forRequest ? "Request" : "Response";

        // First time: save original headers from the full message
        if (originalHeaders == null) {
            originalHeaders = new ArrayList<>(lastParsed.headers());
            originalStartLine = lastParsed.startLine();
            originalBody = lastParsed.rawBody();
            hiddenHeaderKeys = new java.util.HashSet<>();
        }

        if (originalHeaders.isEmpty()) { info("No headers to minimize."); return; }

        // Build primary header checkboxes
        JPanel checkPanel = new JPanel();
        checkPanel.setLayout(new BoxLayout(checkPanel, BoxLayout.Y_AXIS));
        List<JCheckBox> checks = new ArrayList<>();

        JLabel primaryLabel = new JLabel("  \u2500\u2500 " + label.toUpperCase() + " HEADERS \u2500\u2500");
        primaryLabel.setFont(new Font(Font.MONOSPACED, Font.BOLD, 11));
        primaryLabel.setForeground(new Color(124, 211, 255));
        checkPanel.add(primaryLabel);
        checkPanel.add(Box.createVerticalStrut(4));

        for (var header : originalHeaders) {
            String name = header.getKey();
            String nameLower = name.toLowerCase();
            boolean isEssential = essentialSet.contains(nameLower);
            boolean isNoise = noiseSet.contains(nameLower);
            boolean isHidden = hiddenHeaderKeys.contains(nameLower);

            JCheckBox cb = new JCheckBox(name + ": " + truncate(header.getValue(), 60));
            if (isHidden) {
                cb.setSelected(false);
            } else {
                cb.setSelected(isEssential || !isNoise);
            }
            cb.setFont(new Font(Font.MONOSPACED, isEssential ? Font.BOLD : Font.PLAIN, 11));
            if (isNoise) cb.setForeground(Color.GRAY);
            if (isEssential) cb.setForeground(new Color(100, 200, 100));
            if (isHidden) cb.setForeground(new Color(255, 160, 80));
            checks.add(cb);
            checkPanel.add(cb);
        }

        // Companion (response/request) headers section
        boolean hasCompanion = companionParsed != null && companionParsed.headers() != null
                && !companionParsed.headers().isEmpty();
        List<JCheckBox> companionChecks = new ArrayList<>();

        if (hasCompanion) {
            boolean compIsReq = companionParsed.isRequest();
            Set<String> compNoise = compIsReq ? NOISE_HEADERS_REQ : NOISE_HEADERS_RES;
            Set<String> compEssential = compIsReq ? ESSENTIAL_HEADERS_REQ : ESSENTIAL_HEADERS_RES;
            String compLabel = compIsReq ? "REQUEST" : "RESPONSE";

            // Initialize companion minimize state
            if (companionOriginalHeaders == null) {
                companionOriginalHeaders = new ArrayList<>(companionParsed.headers());
                companionOriginalStartLine = companionParsed.startLine();
                companionOriginalBody = companionParsed.rawBody();
                companionHiddenHeaderKeys = new java.util.HashSet<>();
            }

            checkPanel.add(Box.createVerticalStrut(10));
            JSeparator sep = new JSeparator();
            sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
            checkPanel.add(sep);
            checkPanel.add(Box.createVerticalStrut(4));

            JLabel compLabelWidget = new JLabel("  \u2500\u2500 " + compLabel + " HEADERS \u2500\u2500");
            compLabelWidget.setFont(new Font(Font.MONOSPACED, Font.BOLD, 11));
            compLabelWidget.setForeground(new Color(134, 239, 172));
            checkPanel.add(compLabelWidget);
            checkPanel.add(Box.createVerticalStrut(4));

            for (var header : companionOriginalHeaders) {
                String name = header.getKey();
                String nameLower = name.toLowerCase();
                boolean isEss = compEssential.contains(nameLower);
                boolean isNoi = compNoise.contains(nameLower);
                boolean isHid = companionHiddenHeaderKeys.contains(nameLower);

                JCheckBox cb = new JCheckBox(name + ": " + truncate(header.getValue(), 60));
                if (isHid) {
                    cb.setSelected(false);
                } else {
                    cb.setSelected(isEss || !isNoi);
                }
                cb.setFont(new Font(Font.MONOSPACED, isEss ? Font.BOLD : Font.PLAIN, 11));
                if (isNoi) cb.setForeground(Color.GRAY);
                if (isEss) cb.setForeground(new Color(100, 200, 100));
                if (isHid) cb.setForeground(new Color(255, 160, 80));
                companionChecks.add(cb);
                checkPanel.add(cb);
            }
        }

        // All checks combined for button actions
        List<JCheckBox> allChecks = new ArrayList<>(checks);
        allChecks.addAll(companionChecks);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton selectAll = new JButton("Show All");
        selectAll.addActionListener(e -> allChecks.forEach(cb -> cb.setSelected(true)));
        JButton selectNone = new JButton("Hide All");
        selectNone.addActionListener(e -> allChecks.forEach(cb -> cb.setSelected(false)));
        JButton selectEssential = new JButton("Only Essential");
        selectEssential.addActionListener(e -> {
            for (int i = 0; i < checks.size(); i++) {
                String hName = originalHeaders.get(i).getKey().toLowerCase();
                checks.get(i).setSelected(essentialSet.contains(hName));
            }
            if (hasCompanion) {
                Set<String> compEss = companionParsed.isRequest() ? ESSENTIAL_HEADERS_REQ : ESSENTIAL_HEADERS_RES;
                for (int i = 0; i < companionChecks.size(); i++) {
                    String hName = companionOriginalHeaders.get(i).getKey().toLowerCase();
                    companionChecks.get(i).setSelected(compEss.contains(hName));
                }
            }
        });
        JButton restoreAll = new JButton("Restore All");
        restoreAll.addActionListener(e -> allChecks.forEach(cb -> cb.setSelected(true)));
        btnPanel.add(selectAll);
        btnPanel.add(selectNone);
        btnPanel.add(selectEssential);
        btnPanel.add(restoreAll);

        JPanel mainP = new JPanel(new BorderLayout(0, 4));
        mainP.add(btnPanel, BorderLayout.NORTH);
        JScrollPane sp = new JScrollPane(checkPanel);
        sp.setPreferredSize(new Dimension(520, hasCompanion ? 450 : 320));
        mainP.add(sp, BorderLayout.CENTER);

        JLabel hint = new JLabel("Green = essential | Gray = noise | Orange = currently hidden. Uncheck to hide, check to restore.");
        hint.setFont(hint.getFont().deriveFont(Font.ITALIC, 10f));
        mainP.add(hint, BorderLayout.SOUTH);

        String title = hasCompanion
                ? "Minimize Headers — Request + Response"
                : "Minimize " + label + " — Toggle Header Visibility";
        int result = JOptionPane.showConfirmDialog(mainPanel, mainP,
                title, JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return;

        // Update primary editor hidden set
        hiddenHeaderKeys.clear();
        for (int i = 0; i < checks.size(); i++) {
            if (!checks.get(i).isSelected()) {
                hiddenHeaderKeys.add(originalHeaders.get(i).getKey().toLowerCase());
            }
        }

        // Rebuild primary editor message
        StringBuilder sb = new StringBuilder();
        sb.append(originalStartLine).append("\r\n");
        int shown = 0;
        for (var h : originalHeaders) {
            if (!hiddenHeaderKeys.contains(h.getKey().toLowerCase())) {
                sb.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
                shown++;
            }
        }
        sb.append("\r\n");
        if (originalBody != null && !originalBody.isEmpty()) sb.append(originalBody);

        setEditorText(sb.toString());
        int hidden = originalHeaders.size() - shown;

        // Update companion if present
        if (hasCompanion && !companionChecks.isEmpty()) {
            companionHiddenHeaderKeys.clear();
            for (int i = 0; i < companionChecks.size(); i++) {
                if (!companionChecks.get(i).isSelected()) {
                    companionHiddenHeaderKeys.add(companionOriginalHeaders.get(i).getKey().toLowerCase());
                }
            }

            StringBuilder csb = new StringBuilder();
            csb.append(companionOriginalStartLine).append("\r\n");
            int compShown = 0;
            for (var h : companionOriginalHeaders) {
                if (!companionHiddenHeaderKeys.contains(h.getKey().toLowerCase())) {
                    csb.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
                    compShown++;
                }
            }
            csb.append("\r\n");
            if (companionOriginalBody != null && !companionOriginalBody.isEmpty()) csb.append(companionOriginalBody);

            // Update companion content and re-parse
            String compText = csb.toString();
            this.companionContent = compText.getBytes();
            try {
                this.companionParsed = HttpMessageParser.parse(compText, companionIsRequest);
            } catch (Exception ignored) {}

            int compHidden = companionOriginalHeaders.size() - compShown;
            String compLabel = companionIsRequest ? "Request" : "Response";
            searchStatus.setText(label + ": " + shown + " visible, " + hidden + " hidden | "
                    + compLabel + ": " + compShown + " visible, " + compHidden + " hidden");
        } else {
            searchStatus.setText(label + ": " + shown + " visible, " + hidden + " hidden (run again to restore)");
        }
    }

    private static String truncate(String s, int max) {
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    /**
     * Envuelve un JScrollPane con un label de sección.
     * Si endpoint != null, lo muestra con word-wrap y es copyable al hacer clic.
     */
    private JPanel wrapWithLabel(String labelText, String endpoint, JScrollPane scrollPane) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(theme.bg);

        Color labelFg = Color.WHITE;
        Color labelBg = theme.isDark() ? new Color(50, 60, 80) : new Color(60, 100, 180);

        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(labelBg);
        header.setBorder(BorderFactory.createEmptyBorder(3, 4, 3, 4));

        // Label del tipo (REQUEST / RESPONSE)
        JLabel label = new JLabel("  " + labelText + "  ");
        label.setFont(theme.editorFont.deriveFont(Font.BOLD, 14f));
        label.setForeground(labelFg);
        label.setOpaque(false);
        header.add(label, BorderLayout.WEST);

        if (endpoint != null && !endpoint.isEmpty()) {
            // JTextArea para word-wrap automático en endpoints largos
            JTextArea epArea = new JTextArea(endpoint);
            epArea.setFont(theme.editorFont.deriveFont(Font.PLAIN, 10f));
            epArea.setForeground(new Color(210, 225, 245));
            epArea.setBackground(labelBg);
            epArea.setEditable(false);
            epArea.setLineWrap(true);
            epArea.setWrapStyleWord(true);
            epArea.setBorder(BorderFactory.createEmptyBorder(1, 4, 1, 4));
            epArea.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            epArea.setToolTipText("Click to copy endpoint");

            final String epText = endpoint;
            epArea.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mouseClicked(java.awt.event.MouseEvent e) {
                    copyToClipboard(epText);
                    epArea.setText(epText + "  (copied!)");
                    new javax.swing.Timer(2000, ev -> {
                        epArea.setText(epText);
                        ((javax.swing.Timer) ev.getSource()).stop();
                    }).start();
                }
            });
            header.add(epArea, BorderLayout.CENTER);
        }

        panel.add(header, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    // ── Secrets & Links ───────────────────────────────────────────────

    private void findSecrets() {
        String text = editorText();
        if (text.isEmpty()) { info("No content."); return; }

        java.util.List<SecretsFinder.Match> matches = SecretsFinder.scan(text);
        if (matches.isEmpty()) {
            searchStatus.setText("No secrets found");
            info("No secrets found in this message.");
            return;
        }

        searchStatus.setText(matches.size() + " secret(s) found!");

        // Highlight matches in editor with red background
        highlightFindings(text, matches.stream()
                .map(SecretsFinder.Match::value)
                .toList());

        // Show dialog
        showFinderDialog("Secrets Finder — " + matches.size() + " result(s)",
                SecretsFinder.format(matches),
                SecretsFinder.formatRaw(matches),
                "Copy TSV");
    }

    private void findLinks() {
        String text = editorText();
        if (text.isEmpty()) { info("No content."); return; }

        java.util.List<LinkFinder.Link> links = LinkFinder.scan(text);
        if (links.isEmpty()) {
            searchStatus.setText("No links found");
            info("No links/endpoints found in this message.");
            return;
        }

        searchStatus.setText(links.size() + " link(s) found!");

        // Highlight in editor
        highlightFindings(text, links.stream()
                .map(LinkFinder.Link::url)
                .distinct()
                .toList());

        // Show dialog with multiple copy options
        String formatted = LinkFinder.format(links);
        String rawAll = LinkFinder.formatRaw(links);
        String rawPaths = LinkFinder.formatPaths(links);

        JTextArea ta = new JTextArea(formatted);
        ta.setEditable(false); ta.setFont(theme.editorFont);
        ta.setBackground(theme.bg); ta.setForeground(theme.fg);
        ta.setLineWrap(true); ta.setWrapStyleWord(true);
        JScrollPane sp = new JScrollPane(ta);
        sp.setPreferredSize(new Dimension(650, 420));

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 0));
        btnPanel.setBackground(theme.bg);

        JButton copyAll = new JButton("Copy All URLs");
        copyAll.addActionListener(e -> { copyToClipboard(rawAll); copyAll.setText("Copied!"); });
        JButton copyPaths = new JButton("Copy Paths Only");
        copyPaths.addActionListener(e -> { copyToClipboard(rawPaths); copyPaths.setText("Copied!"); });
        JButton copyFull = new JButton("Copy Full Report");
        copyFull.addActionListener(e -> { copyToClipboard(formatted); copyFull.setText("Copied!"); });

        btnPanel.add(copyAll);
        btnPanel.add(copyPaths);
        btnPanel.add(copyFull);

        JPanel p = new JPanel(new BorderLayout(0, 8));
        p.add(sp, BorderLayout.CENTER);
        p.add(btnPanel, BorderLayout.SOUTH);

        JOptionPane.showMessageDialog(mainPanel, p,
                "Link Finder — " + links.size() + " result(s)",
                JOptionPane.PLAIN_MESSAGE);
    }

    /**
     * Resalta en el editor los valores encontrados (secrets o links).
     * Usa color rojo translúcido para distinguirse del search amarillo.
     */
    private void highlightFindings(String text, java.util.List<String> values) {
        try {
            javax.swing.text.Highlighter hl = editor.getHighlighter();
            // Clear previous finding highlights to prevent accumulation
            hl.removeAllHighlights();
            Color findingColor = theme.isDark()
                    ? new Color(180, 60, 60, 90)
                    : new Color(255, 120, 120, 100);
            javax.swing.text.DefaultHighlighter.DefaultHighlightPainter painter =
                    new javax.swing.text.DefaultHighlighter.DefaultHighlightPainter(findingColor);

            for (String val : values) {
                // Truncated values end with "..." — use the non-truncated prefix
                String searchVal = val.endsWith("...") ? val.substring(0, val.length() - 3) : val;
                if (searchVal.length() < 3) continue;
                int idx = 0;
                while ((idx = text.indexOf(searchVal, idx)) >= 0) {
                    hl.addHighlight(idx, idx + searchVal.length(), painter);
                    idx += searchVal.length();
                }
            }
        } catch (Exception ignored) {}
    }

    /**
     * Diálogo genérico para Secrets con botón de copiar TSV.
     */
    private void showFinderDialog(String title, String formatted, String raw, String copyLabel) {
        JTextArea ta = new JTextArea(formatted);
        ta.setEditable(false); ta.setFont(theme.editorFont);
        ta.setBackground(theme.bg); ta.setForeground(theme.fg);
        ta.setLineWrap(true); ta.setWrapStyleWord(true);
        JScrollPane sp = new JScrollPane(ta);
        sp.setPreferredSize(new Dimension(650, 420));

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 0));
        btnPanel.setBackground(theme.bg);

        JButton copyRaw = new JButton(copyLabel);
        copyRaw.addActionListener(e -> { copyToClipboard(raw); copyRaw.setText("Copied!"); });
        JButton copyFull = new JButton("Copy Full Report");
        copyFull.addActionListener(e -> { copyToClipboard(formatted); copyFull.setText("Copied!"); });

        btnPanel.add(copyRaw);
        btnPanel.add(copyFull);

        JPanel p = new JPanel(new BorderLayout(0, 8));
        p.add(sp, BorderLayout.CENTER);
        p.add(btnPanel, BorderLayout.SOUTH);

        JOptionPane.showMessageDialog(mainPanel, p, title, JOptionPane.PLAIN_MESSAGE);
    }

    // ── Template Variables ──────────────────────────────────────────

    /** Opens the Template Variables Manager dialog */
    private void openTemplateVarsManager() {
        // Provide insert callback so user can insert vars/values directly into the editor
        java.util.function.Consumer<String> insertCb = text -> {
            try {
                int pos = editor.getCaretPosition();
                String sel = editor.getSelectedText();
                if (sel != null) {
                    int start = editor.getSelectionStart();
                    int end = editor.getSelectionEnd();
                    editor.getDocument().remove(start, end - start);
                    editor.getDocument().insertString(start, text, null);
                } else {
                    editor.getDocument().insertString(pos, text, null);
                }
                modified = true;
            } catch (Exception ignored) {}
        };
        boolean changed = TemplateVars.showManagerDialog(mainPanel, theme.bg, theme.fg, theme.editorFont, insertCb);
        if (changed) {
            int defined = TemplateVars.getAll().size();
            int placeholders = TemplateVars.countPlaceholders(editorText());
            String msg = defined + " var(s) defined";
            if (placeholders > 0) msg += " \u2014 " + placeholders + " {{var}} in editor, auto-replaced on Send";
            searchStatus.setText(msg);
        }
    }

    /** Quick-set: save selected text as a named variable */
    private void quickSetVariable() {
        String sel = editor.getSelectedText();
        if (sel == null || sel.isEmpty()) { info("Select text first."); return; }
        if (TemplateVars.quickSet(mainPanel, sel)) {
            searchStatus.setText("Variable saved \u2014 use {{name}} anywhere");
        }
    }

    /**
     * Insert a {{variable}} placeholder at the current caret position,
     * or replace the current selection with the chosen variable placeholder.
     * Shows a list of defined variables to pick from.
     */
    private void insertVariableAtCaret() {
        var vars = TemplateVars.getAll();
        if (vars.isEmpty()) {
            info("No variables defined.\nOpen the Variable Manager first (Ctrl+T).");
            return;
        }
        // Build list: "varName  =  value (preview)"
        String[] names = vars.keySet().toArray(new String[0]);
        String[] display = new String[names.length];
        for (int i = 0; i < names.length; i++) {
            String val = vars.get(names[i]);
            String preview = val.length() > 40 ? val.substring(0, 40) + "..." : val;
            display[i] = names[i] + "  \u2192  " + preview;
        }
        String chosen = (String) JOptionPane.showInputDialog(mainPanel,
                "Select variable to insert as {{name}}:",
                "Insert Variable", JOptionPane.PLAIN_MESSAGE, null, display, display[0]);
        if (chosen == null) return;
        // Find the variable name from the display string
        int idx = java.util.Arrays.asList(display).indexOf(chosen);
        if (idx < 0) return;
        String placeholder = "{{" + names[idx] + "}}";
        // Replace selection or insert at caret
        try {
            int selStart = editor.getSelectionStart();
            int selEnd = editor.getSelectionEnd();
            if (selStart != selEnd) {
                editor.getDocument().remove(selStart, selEnd - selStart);
            }
            editor.getDocument().insertString(editor.getCaretPosition(), placeholder, null);
            modified = true;
            searchStatus.setText("Inserted " + placeholder);
        } catch (Exception e) {
            info("Error inserting variable: " + e.getMessage());
        }
    }

    // ── Editor History ─────────────────────────────────────────────

    /** Show the history browser and optionally restore a version */
    private void showHistory() {
        String restored = editorHistory.showBrowserDialog(mainPanel, theme.bg, theme.fg, theme.editorFont);
        if (restored != null) {
            editorHistory.save("Before Restore", editorText());
            updating = true;
            try {
                editor.setText(restored);
                lastParsed = HttpMessageParser.parse(restored, isRequest);
                renderWithOverlays();
                editor.setCaretPosition(0);
            } finally {
                updating = false;
            }
            modified = true;
            updateStats();
            searchStatus.setText("Restored from history");
        }
    }

    /** Manually save a snapshot — prompts for a custom name */
    private void saveManualSnapshot() {
        String text = editorText();
        if (text.isEmpty()) { info("No content to save."); return; }
        String name = JOptionPane.showInputDialog(mainPanel,
                "Snapshot name:", "Save Snapshot", JOptionPane.PLAIN_MESSAGE);
        if (name == null) return; // cancelled
        if (name.isBlank()) name = "Manual snapshot";
        editorHistory.save(name.trim(), text);
        searchStatus.setText("Snapshot '" + name.trim() + "' saved (" + editorHistory.size() + " total)");
    }

    // ── Undo / Redo ─────────────────────────────────────────────────

    private void undo() {
        try { if (undoManager.canUndo()) undoManager.undo(); } catch (CannotUndoException ignored) {}
    }
    private void redo() {
        try { if (undoManager.canRedo()) undoManager.redo(); } catch (CannotRedoException ignored) {}
    }

    // ── Shortcuts ───────────────────────────────────────────────────

    private void bindShortcuts(JComponent comp) {
        InputMap im = comp.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        ActionMap am = comp.getActionMap();
        bind(im, am, KeyEvent.VK_F, MOD, "focusSearch", () -> { searchField.requestFocusInWindow(); searchField.selectAll(); });
        bind(im, am, KeyEvent.VK_H, MOD, "focusReplace", () -> { replaceField.requestFocusInWindow(); replaceField.selectAll(); });
        bind(im, am, KeyEvent.VK_G, MOD, "findNext", this::searchNext);
        bind(im, am, KeyEvent.VK_G, MOD | InputEvent.SHIFT_DOWN_MASK, "findPrev", this::searchPrev);
        bind(im, am, KeyEvent.VK_ESCAPE, 0, "escape", () -> { searchManager.clearMatchHighlights(); hideDecoder(); editor.requestFocusInWindow(); });
        bind(im, am, KeyEvent.VK_L, MOD, "toggleLines", () -> { linesCheckbox.setSelected(!linesCheckbox.isSelected()); toggleLineNumbers(); });
        bind(im, am, KeyEvent.VK_B, MOD, "togglePretty", this::togglePretty);
        bind(im, am, KeyEvent.VK_S, MOD, "export", this::exportToFile);
        bind(im, am, KeyEvent.VK_T, MOD, "varsManager", this::openTemplateVarsManager);
        // AI panel toggle is handled globally via AWTEventListener (Shift+Option+X / Shift+Ctrl+X)
    }
    private void bindEditorShortcuts() {
        InputMap im = editor.getInputMap(JComponent.WHEN_FOCUSED);
        ActionMap am = editor.getActionMap();
        // Undo / Redo (custom — JTextPane doesn't bind these by default)
        bind(im, am, KeyEvent.VK_Z, MOD, "undo", this::undo);
        bind(im, am, KeyEvent.VK_Z, MOD | InputEvent.SHIFT_DOWN_MASK, "redo", this::redo);
        bind(im, am, KeyEvent.VK_Y, MOD, "redoY", this::redo);
        bind(im, am, KeyEvent.VK_F, MOD, "focusSearch2", () -> { searchField.requestFocusInWindow(); searchField.selectAll(); });
        bind(im, am, KeyEvent.VK_S, MOD | InputEvent.SHIFT_DOWN_MASK, "snapShortcut", this::openSnapWindow);
        // NOTE: Do NOT bind VK_C/VK_V/VK_X/VK_A here.
        // JTextPane (StyledEditorKit) already handles Copy/Cut/Paste/SelectAll natively
        // via DefaultEditorKit actions. Overriding them breaks clipboard operations.
    }
    private static void bind(InputMap im, ActionMap am, int key, int mod, String name, Runnable action) {
        im.put(KeyStroke.getKeyStroke(key, mod), name);
        am.put(name, new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { action.run(); }
        });
    }

    // ── Cleanup (prevents memory leaks on editor disposal) ────────

    /**
     * Release all resources held by this editor.
     * Call when the editor is no longer needed (e.g., tab closed, extension unloaded).
     */
    public void cleanup() {
        // 1. Cancel any pending async render
        if (asyncRenderWorker != null && !asyncRenderWorker.isDone()) {
            asyncRenderWorker.cancel(true);
            asyncRenderWorker = null;
        }

        // 2. Stop feedback timer
        if (feedbackTimer != null) {
            feedbackTimer.stop();
            feedbackTimer = null;
        }

        // 3. Remove document listeners from current document
        Document doc = editor.getDocument();
        if (doc instanceof javax.swing.text.DefaultStyledDocument sDoc) {
            sDoc.removeUndoableEditListener(undoManager);
            sDoc.removeDocumentListener(docModListener);
            if (lineGutter != null) sDoc.removeDocumentListener(lineGutter);
        }

        // 4. Clear undo history
        undoManager.discardAllEdits();

        // 5. Clear document cache (releases styled documents and their associated resources)
        docCache.clear();

        // 6. Cleanup AI panel
        if (aiPanel != null) {
            aiPanel.cleanup();
        }

        // 7. Clear references to prevent GC roots
        currentContent = null;
        lastParsed = null;
        companionContent = null;
        companionParsed = null;
        originalHeaders = null;
        companionOriginalHeaders = null;
        originalService = null;
    }

    // ── Helpers ─────────────────────────────────────────────────────

    private void markModified() { if (!updating) modified = true; }
    private String editorText() {
        try { return editor.getDocument().getText(0, editor.getDocument().getLength()); }
        catch (Exception e) { return ""; }
    }
    private void copyToClipboard(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }
    private void info(String msg) {
        JOptionPane.showMessageDialog(mainPanel, msg, "Pro Color View", JOptionPane.INFORMATION_MESSAGE);
    }
    private void showDialog(String title, String content) {
        JTextArea ta = new JTextArea(content);
        ta.setEditable(false); ta.setFont(theme.editorFont);
        ta.setBackground(theme.bg); ta.setForeground(theme.fg);
        ta.setLineWrap(true); ta.setWrapStyleWord(true);
        JScrollPane sp = new JScrollPane(ta);
        sp.setPreferredSize(new Dimension(600, 400));
        JButton cb = new JButton("Copy to Clipboard");
        cb.addActionListener(e -> { copyToClipboard(content); cb.setText("Copied!"); });
        JPanel p = new JPanel(new BorderLayout(0, 8));
        p.add(sp, BorderLayout.CENTER); p.add(cb, BorderLayout.SOUTH);
        JOptionPane.showMessageDialog(mainPanel, p, title, JOptionPane.PLAIN_MESSAGE);
    }
}
