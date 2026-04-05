package com.procolorview.ai;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.procolorview.ai.AiConfig.Provider;
import com.procolorview.ai.AiExecutor.TestCase;
import com.procolorview.theme.ProColorTheme;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * AI-powered vulnerability testing panel for Pro Color View.
 *
 * Two-phase execution flow:
 *   Phase 1: Send request + prompt to AI → AI generates test payloads (```testplan block)
 *   Phase 2: Execute each payload via Burp API → Collect responses
 *   Phase 3: Send results back to AI → AI provides final verdict
 *
 * Integrates into ProColorEditor as a togglable bottom panel.
 */
public class AiPanel extends JPanel {

    private final ProColorTheme theme;
    private MontoyaApi burpApi;

    // Suppliers from ProColorEditor
    private Supplier<String> requestSupplier;    // raw request text
    private Supplier<String> responseSupplier;   // raw response text
    private Supplier<byte[]> requestBytesSupplier; // raw request bytes for Burp sending
    private Supplier<HttpService> serviceSupplier;  // target host/port/https

    // UI Components
    private JComboBox<Provider> providerCombo;
    private JComboBox<String> promptCombo;
    private JTextPane resultsPane;
    private JButton executeBtn;
    private JButton stopBtn;
    private JLabel statusLabel;
    private JProgressBar progressBar;

    // State
    private volatile boolean cancelled = false;
    private SwingWorker<Void, String> currentWorker;

    public AiPanel(ProColorTheme theme, MontoyaApi api) {
        super(new BorderLayout(0, 0));
        this.theme = theme;
        this.burpApi = api;

        Color panelBg = theme.isDark() ? new Color(18, 22, 30) : new Color(242, 244, 248);
        setBackground(panelBg);
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0,
                        theme.isDark() ? new Color(55, 65, 85) : new Color(190, 195, 210)),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)
        ));

        add(createControlBar(panelBg), BorderLayout.NORTH);
        add(createResultsPanel(panelBg), BorderLayout.CENTER);

        setPreferredSize(new Dimension(0, 320));
        setVisible(false);
    }

    /** Set suppliers for getting the current request/response text and Burp objects */
    public void setContentSuppliers(Supplier<String> request, Supplier<String> response,
                                     Supplier<byte[]> requestBytes, Supplier<HttpService> service) {
        this.requestSupplier = request;
        this.responseSupplier = response;
        this.requestBytesSupplier = requestBytes;
        this.serviceSupplier = service;
    }

    public void toggle() {
        boolean willShow = !isVisible();
        setVisible(willShow);
        if (willShow) {
            revalidate(); repaint();
        } else {
            // Stop any running AI execution when hiding to prevent worker leaks
            stopExecution();
        }
    }

    // ── Control Bar ────────────────────────────────────────────────

    private JPanel createControlBar(Color bg) {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        bar.setBackground(bg);

        providerCombo = new JComboBox<>(Provider.values());
        providerCombo.setSelectedItem(AiConfig.getSelectedProvider());
        providerCombo.setFont(theme.editorFont.deriveFont(Font.BOLD, 11f));
        providerCombo.setBackground(theme.searchFieldBg);
        providerCombo.setForeground(theme.isDark() ? new Color(100, 200, 255) : new Color(0, 100, 180));
        providerCombo.setPreferredSize(new Dimension(170, 24));
        providerCombo.addActionListener(e -> {
            Provider sel = (Provider) providerCombo.getSelectedItem();
            if (sel != null) AiConfig.setSelectedProvider(sel);
        });

        JButton settingsBtn = smallBtn("\u2699", "Configure API Keys & Models");
        settingsBtn.addActionListener(e -> showApiKeyDialog());

        promptCombo = new JComboBox<>();
        refreshPromptCombo();
        promptCombo.setFont(theme.editorFont.deriveFont(11f));
        promptCombo.setBackground(theme.searchFieldBg);
        promptCombo.setForeground(theme.fg);
        promptCombo.setPreferredSize(new Dimension(180, 24));

        JButton editPromptsBtn = smallBtn("\u270E", "Edit Prompt Templates");
        editPromptsBtn.addActionListener(e -> { showPromptManagerDialog(); refreshPromptCombo(); });

        JButton newPromptBtn = smallBtn("+", "Create New Prompt");
        newPromptBtn.setForeground(new Color(100, 220, 100));
        newPromptBtn.addActionListener(e -> { showNewPromptDialog(); refreshPromptCombo(); });

        executeBtn = new JButton("\u25B6 Execute");
        executeBtn.setFont(theme.editorFont.deriveFont(Font.BOLD, 11f));
        executeBtn.setForeground(new Color(80, 220, 120));
        executeBtn.setMargin(new Insets(2, 8, 2, 8));
        executeBtn.addActionListener(e -> executeFullPipeline());

        stopBtn = new JButton("\u25A0 Stop");
        stopBtn.setFont(theme.editorFont.deriveFont(Font.BOLD, 11f));
        stopBtn.setForeground(new Color(255, 100, 100));
        stopBtn.setMargin(new Insets(2, 8, 2, 8));
        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> stopExecution());

        JButton copyBtn = smallBtn("\u2398", "Copy AI results to clipboard");
        copyBtn.addActionListener(e -> {
            String text = resultsPane.getText();
            if (!text.isBlank()) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(text), null);
                statusLabel.setText("Copied!");
            }
        });

        JButton clearBtn = smallBtn("\u2715", "Clear results");
        clearBtn.setForeground(new Color(200, 100, 100));
        clearBtn.addActionListener(e -> { resultsPane.setText(""); statusLabel.setText("Ready"); });

        statusLabel = new JLabel("Ready");
        statusLabel.setFont(theme.editorFont.deriveFont(Font.ITALIC, 10f));
        statusLabel.setForeground(theme.bodyHint);

        progressBar = new JProgressBar();
        progressBar.setPreferredSize(new Dimension(100, 14));
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);

        JLabel provLabel = new JLabel("AI:");
        provLabel.setFont(theme.editorFont.deriveFont(Font.BOLD, 11f));
        provLabel.setForeground(new Color(255, 180, 60));

        JLabel promptLabel = new JLabel("Prompt:");
        promptLabel.setFont(theme.editorFont.deriveFont(Font.BOLD, 11f));
        promptLabel.setForeground(new Color(180, 140, 255));

        bar.add(provLabel);
        bar.add(providerCombo);
        bar.add(settingsBtn);
        bar.add(createSep());
        bar.add(promptLabel);
        bar.add(promptCombo);
        bar.add(editPromptsBtn);
        bar.add(newPromptBtn);
        bar.add(createSep());
        bar.add(executeBtn);
        bar.add(stopBtn);
        bar.add(createSep());
        bar.add(copyBtn);
        bar.add(clearBtn);
        bar.add(Box.createHorizontalStrut(6));
        bar.add(progressBar);
        bar.add(Box.createHorizontalStrut(4));
        bar.add(statusLabel);

        return bar;
    }

    // ── Results Panel ──────────────────────────────────────────────

    private JScrollPane createResultsPanel(Color bg) {
        resultsPane = new JTextPane();
        resultsPane.setEditable(false);
        resultsPane.setFont(theme.editorFont.deriveFont(12f));
        resultsPane.setBackground(bg);
        resultsPane.setForeground(theme.fg);
        resultsPane.setCaretColor(theme.caret);

        appendStyled("\u2139 Select a prompt and click Execute to analyze & test the current request.\n", theme.bodyHint, false);
        appendStyled("Configure API keys with the \u2699 button. Tests are executed through Burp.\n", theme.bodyHint, false);

        JScrollPane sp = new JScrollPane(resultsPane);
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.getViewport().setBackground(bg);
        return sp;
    }

    // ══════════════════════════════════════════════════════════════
    //  FULL EXECUTION PIPELINE (3 phases)
    // ══════════════════════════════════════════════════════════════

    private void executeFullPipeline() {
        // Validate
        Provider provider = (Provider) providerCombo.getSelectedItem();
        if (provider == null) return;
        String apiKey = AiConfig.getApiKey(provider);
        if (apiKey.isBlank()) {
            showError("No API key configured for " + provider.displayName + ". Click \u2699 to add one.");
            return;
        }
        String promptName = (String) promptCombo.getSelectedItem();
        if (promptName == null || promptName.isBlank()) { showError("No prompt selected."); return; }
        String promptTemplate = AiConfig.getPrompt(promptName);
        if (promptTemplate.isBlank()) { showError("Prompt template is empty."); return; }

        // Get content
        String requestText = (requestSupplier != null) ? requestSupplier.get() : "";
        String responseText = (responseSupplier != null) ? responseSupplier.get() : "";
        byte[] rawRequestBytes = (requestBytesSupplier != null) ? requestBytesSupplier.get() : null;
        HttpService httpService = (serviceSupplier != null) ? serviceSupplier.get() : null;

        String finalPrompt = promptTemplate
                .replace("{{request}}", requestText)
                .replace("{{response}}", responseText);

        String model = AiConfig.getModel(provider);

        // Clear and start
        resultsPane.setText("");
        cancelled = false;
        setExecuting(true);

        appendStyled("\u23F3 Phase 1: Sending to " + provider.displayName + " (" + model + ")...\n", new Color(100, 200, 255), true);
        appendStyled("Prompt: " + promptName + "\n", theme.bodyHint, false);
        appendStyled(repeat("\u2500", 60) + "\n\n", theme.bodyHint, false);

        currentWorker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                try {
                    // ── Phase 1: AI analysis + payload generation ──
                    publish("[PHASE1_START]");
                    // User's prompt is primary; testplan format appended as additional instruction
                    String aiResponse = AiExecutor.callAiSync(
                            provider, apiKey, model,
                            AiExecutor.SYSTEM_PROMPT,
                            finalPrompt + AiExecutor.TESTPLAN_APPENDIX);

                    if (cancelled) return null;
                    publish("[PHASE1_DONE]" + aiResponse);

                    // Parse test plan from AI response
                    List<TestCase> tests = AiExecutor.parseTestPlan(aiResponse);

                    if (tests.isEmpty() || rawRequestBytes == null || httpService == null) {
                        // No tests or no request to send — just show the analysis
                        if (tests.isEmpty()) {
                            publish("[NO_TESTS]");
                        } else {
                            publish("[NO_REQUEST]");
                        }
                        return null;
                    }

                    // ── Phase 2: Execute tests via Burp ──
                    publish("[PHASE2_START]" + tests.size());
                    List<String> testResults = new ArrayList<>();

                    for (int i = 0; i < tests.size() && !cancelled; i++) {
                        TestCase tc = tests.get(i);
                        publish("[TEST_START]" + (i + 1) + "/" + tests.size() + ": " + tc.desc());

                        try {
                            // Modify request with payload
                            byte[] modifiedBytes = injectPayload(rawRequestBytes, tc);
                            if (modifiedBytes == null) {
                                String result = formatTestResult(i + 1, tc, -1, -1, 0,
                                        "[Could not inject payload — parameter not found]");
                                testResults.add(result);
                                publish("[TEST_DONE]" + result);
                                continue;
                            }

                            // Send through Burp
                            String modifiedStr = new String(modifiedBytes, StandardCharsets.ISO_8859_1);
                            modifiedStr = modifiedStr.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n");
                            HttpRequest burpReq = HttpRequest.httpRequest(httpService,
                                    ByteArray.byteArray(modifiedStr));

                            long startTime = System.currentTimeMillis();
                            var burpResp = burpApi.http().sendRequest(burpReq);
                            long elapsed = System.currentTimeMillis() - startTime;

                            HttpResponse resp = burpResp.response();
                            if (resp == null) {
                                String result = formatTestResult(i + 1, tc, -1, elapsed, 0,
                                        "[No response — connection failed or timeout]");
                                testResults.add(result);
                                publish("[TEST_DONE]" + result);
                                continue;
                            }

                            int statusCode = resp.statusCode();
                            int bodyLen = resp.body() != null ? resp.body().length() : 0;
                            String bodySnippet = "";
                            if (resp.body() != null) {
                                bodySnippet = resp.body().toString();
                                if (bodySnippet.length() > 500)
                                    bodySnippet = bodySnippet.substring(0, 500) + "...[truncated]";
                            }

                            // Check if payload is reflected in response
                            boolean reflected = bodySnippet.contains(tc.payload());

                            String result = formatTestResult(i + 1, tc, statusCode, elapsed, bodyLen,
                                    bodySnippet);
                            if (reflected) result += "\n    ** PAYLOAD REFLECTED IN RESPONSE **";
                            testResults.add(result);
                            publish("[TEST_DONE]" + result);

                        } catch (Exception e) {
                            String result = formatTestResult(i + 1, tc, -1, -1, 0,
                                    "[Error: " + e.getMessage() + "]");
                            testResults.add(result);
                            publish("[TEST_DONE]" + result);
                        }
                    }

                    if (cancelled) return null;

                    // ── Phase 3: Send results to AI for verdict ──
                    publish("[PHASE3_START]");

                    StringBuilder phase2Prompt = new StringBuilder();
                    phase2Prompt.append("Original request:\n").append(requestText).append("\n\n");
                    phase2Prompt.append("Test execution results (").append(testResults.size())
                            .append(" tests):\n\n");
                    for (String r : testResults) {
                        phase2Prompt.append(r).append("\n\n");
                    }
                    phase2Prompt.append("\nAnalyze these results. Identify confirmed vulnerabilities, ");
                    phase2Prompt.append("likely vulnerabilities, and negative results. ");
                    phase2Prompt.append("Provide severity ratings and next steps.");

                    String verdict = AiExecutor.callAiSync(
                            provider, apiKey, model,
                            AiExecutor.SYSTEM_PROMPT_PHASE2,
                            phase2Prompt.toString());

                    if (!cancelled) {
                        publish("[PHASE3_DONE]" + verdict);
                    }

                } catch (Exception e) {
                    if (!cancelled) {
                        publish("[ERROR]" + e.getClass().getSimpleName() + ": " + e.getMessage());
                    }
                }
                return null;
            }

            @Override
            protected void process(List<String> chunks) {
                for (String msg : chunks) {
                    if (msg.startsWith("[PHASE1_START]")) {
                        // Already shown above
                    } else if (msg.startsWith("[PHASE1_DONE]")) {
                        String aiResp = msg.substring("[PHASE1_DONE]".length());
                        appendStyled("\u2705 Phase 1 Complete — AI Analysis\n", new Color(80, 220, 120), true);
                        appendStyled(repeat("\u2500", 60) + "\n", theme.bodyHint, false);
                        // Show analysis (but strip the testplan block from display)
                        String displayText = aiResp.replaceAll("```testplan\\s*\\n.*?\\n\\s*```", "[Test plan generated — see execution below]");
                        renderFormattedResult(displayText);
                        appendStyled("\n" + repeat("\u2500", 60) + "\n\n", theme.bodyHint, false);
                    } else if (msg.startsWith("[NO_TESTS]")) {
                        appendStyled("\u26A0 No structured test plan found in AI response. Showing analysis only.\n",
                                new Color(255, 180, 60), true);
                    } else if (msg.startsWith("[NO_REQUEST]")) {
                        appendStyled("\u26A0 No request available to execute tests. Load a request first.\n",
                                new Color(255, 180, 60), true);
                    } else if (msg.startsWith("[PHASE2_START]")) {
                        int count = Integer.parseInt(msg.substring("[PHASE2_START]".length()));
                        progressBar.setIndeterminate(false);
                        progressBar.setMaximum(count);
                        progressBar.setValue(0);
                        progressBar.setString("0/" + count);
                        appendStyled("\n\u23F3 Phase 2: Executing " + count + " tests via Burp...\n",
                                new Color(100, 200, 255), true);
                        appendStyled(repeat("\u2500", 60) + "\n\n", theme.bodyHint, false);
                    } else if (msg.startsWith("[TEST_START]")) {
                        String info = msg.substring("[TEST_START]".length());
                        statusLabel.setText("Testing " + info);
                        // Update progress
                        try {
                            int current = Integer.parseInt(info.split("/")[0]);
                            int total = Integer.parseInt(info.split("/")[1].split(":")[0]);
                            progressBar.setValue(current);
                            progressBar.setString(current + "/" + total);
                        } catch (Exception ignored) {}
                    } else if (msg.startsWith("[TEST_DONE]")) {
                        String result = msg.substring("[TEST_DONE]".length());
                        // Color based on whether reflected or error
                        if (result.contains("PAYLOAD REFLECTED")) {
                            appendStyled(result + "\n", new Color(255, 80, 80), false);
                        } else if (result.contains("[Error") || result.contains("[Could not") || result.contains("[No response")) {
                            appendStyled(result + "\n", new Color(255, 180, 60), false);
                        } else {
                            appendStyled(result + "\n", theme.fg, false);
                        }
                    } else if (msg.startsWith("[PHASE3_START]")) {
                        appendStyled("\n" + repeat("\u2500", 60) + "\n", theme.bodyHint, false);
                        appendStyled("\u23F3 Phase 3: AI analyzing results...\n\n", new Color(100, 200, 255), true);
                        progressBar.setIndeterminate(true);
                        progressBar.setString("Analyzing...");
                    } else if (msg.startsWith("[PHASE3_DONE]")) {
                        String verdict = msg.substring("[PHASE3_DONE]".length());
                        appendStyled("\u2705 FINAL VERDICT\n", new Color(255, 200, 80), true);
                        appendStyled(repeat("\u2550", 60) + "\n\n", new Color(255, 200, 80), false);
                        renderFormattedResult(verdict);
                        appendStyled("\n" + repeat("\u2550", 60) + "\n", new Color(255, 200, 80), false);
                    } else if (msg.startsWith("[ERROR]")) {
                        String error = msg.substring("[ERROR]".length());
                        appendStyled("\n\u274C Error: " + error + "\n", new Color(255, 80, 80), true);
                    }
                }
            }

            @Override
            protected void done() {
                setExecuting(false);
                if (cancelled) {
                    appendStyled("\n\u25A0 Execution cancelled.\n", new Color(255, 180, 60), true);
                    statusLabel.setText("Cancelled");
                } else {
                    statusLabel.setText("Done");
                }
            }
        };
        currentWorker.execute();
    }

    // ── Request modification (inject payload) ──────────────────────

    /**
     * Inject a test payload into the raw HTTP request bytes.
     * Modifies the specified parameter based on its location.
     */
    private byte[] injectPayload(byte[] originalRequest, TestCase tc) {
        String reqStr = new String(originalRequest, StandardCharsets.ISO_8859_1);
        String param = tc.param();
        String origVal = tc.value();
        String payload = tc.payload();
        String where = tc.where().toLowerCase();
        boolean modified = false;

        switch (where) {
            case "query", "url_param", "url" -> {
                // Try URL-encoded replacement in query string
                // First find the first line (request line)
                int firstLineEnd = reqStr.indexOf('\n');
                if (firstLineEnd < 0) firstLineEnd = reqStr.length();
                String firstLine = reqStr.substring(0, firstLineEnd);

                // Try exact match: param=value
                String searchExact = param + "=" + origVal;
                String replaceExact = param + "=" + payload;
                if (firstLine.contains(searchExact)) {
                    reqStr = reqStr.substring(0, firstLineEnd).replace(searchExact, replaceExact)
                            + reqStr.substring(firstLineEnd);
                    modified = true;
                }
                // Try URL-encoded match
                if (!modified) {
                    try {
                        String encodedOrig = URLEncoder.encode(origVal, StandardCharsets.UTF_8);
                        String searchEnc = param + "=" + encodedOrig;
                        if (firstLine.contains(searchEnc)) {
                            String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);
                            reqStr = reqStr.substring(0, firstLineEnd).replace(searchEnc, param + "=" + encodedPayload)
                                    + reqStr.substring(firstLineEnd);
                            modified = true;
                        }
                    } catch (Exception ignored) {}
                }
            }

            case "body", "body_param", "form" -> {
                // Find body (after \r\n\r\n or \n\n)
                int bodySep = reqStr.indexOf("\r\n\r\n");
                int bodyStart = bodySep >= 0 ? bodySep + 4 : -1;
                if (bodyStart < 0) { bodySep = reqStr.indexOf("\n\n"); bodyStart = bodySep >= 0 ? bodySep + 2 : -1; }
                if (bodyStart >= 0) {
                    String headers = reqStr.substring(0, bodyStart);
                    String body = reqStr.substring(bodyStart);

                    // Form body: param=value
                    String searchExact = param + "=" + origVal;
                    if (body.contains(searchExact)) {
                        body = body.replace(searchExact, param + "=" + payload);
                        modified = true;
                    }
                    // URL-encoded body
                    if (!modified) {
                        try {
                            String searchEnc = param + "=" + URLEncoder.encode(origVal, StandardCharsets.UTF_8);
                            if (body.contains(searchEnc)) {
                                body = body.replace(searchEnc, param + "=" +
                                        URLEncoder.encode(payload, StandardCharsets.UTF_8));
                                modified = true;
                            }
                        } catch (Exception ignored) {}
                    }
                    if (modified) {
                        // Update Content-Length
                        reqStr = headers + body;
                        reqStr = updateContentLength(reqStr, body.length());
                    }
                }
            }

            case "json" -> {
                // JSON body: replace "param": "value" or "param": value
                int bodySep = reqStr.indexOf("\r\n\r\n");
                int bodyStart = bodySep >= 0 ? bodySep + 4 : -1;
                if (bodyStart < 0) { bodySep = reqStr.indexOf("\n\n"); bodyStart = bodySep >= 0 ? bodySep + 2 : -1; }
                if (bodyStart >= 0) {
                    String headers = reqStr.substring(0, bodyStart);
                    String body = reqStr.substring(bodyStart);

                    // Try "param": "value"
                    String search1 = "\"" + param + "\":\"" + origVal + "\"";
                    String search2 = "\"" + param + "\": \"" + origVal + "\"";
                    String search3 = "\"" + param + "\":" + origVal; // numeric

                    if (body.contains(search1)) {
                        body = body.replace(search1, "\"" + param + "\":\"" + payload + "\"");
                        modified = true;
                    } else if (body.contains(search2)) {
                        body = body.replace(search2, "\"" + param + "\": \"" + payload + "\"");
                        modified = true;
                    } else if (body.contains(search3)) {
                        // For numeric, try injecting as string
                        body = body.replace(search3, "\"" + param + "\":\"" + payload + "\"");
                        modified = true;
                    }
                    if (modified) {
                        reqStr = headers + body;
                        reqStr = updateContentLength(reqStr, body.length());
                    }
                }
            }

            case "header" -> {
                // Find header line and replace value
                String headerSearch = param + ": " + origVal;
                String headerReplace = param + ": " + payload;
                if (reqStr.contains(headerSearch)) {
                    reqStr = reqStr.replace(headerSearch, headerReplace);
                    modified = true;
                }
                // Case-insensitive fallback
                if (!modified) {
                    String lower = reqStr.toLowerCase();
                    String lowerSearch = param.toLowerCase() + ": " + origVal.toLowerCase();
                    int idx = lower.indexOf(lowerSearch);
                    if (idx >= 0) {
                        reqStr = reqStr.substring(0, idx) + param + ": " + payload +
                                reqStr.substring(idx + lowerSearch.length());
                        modified = true;
                    }
                }
            }

            case "cookie" -> {
                // Find in Cookie header: name=value
                String cookieSearch = param + "=" + origVal;
                if (reqStr.contains(cookieSearch)) {
                    reqStr = reqStr.replace(cookieSearch, param + "=" + payload);
                    modified = true;
                }
            }

            case "path" -> {
                // Replace value in the URL path
                int firstLineEnd = reqStr.indexOf('\n');
                if (firstLineEnd < 0) firstLineEnd = reqStr.length();
                String firstLine = reqStr.substring(0, firstLineEnd);
                if (firstLine.contains(origVal)) {
                    reqStr = firstLine.replace(origVal, payload) + reqStr.substring(firstLineEnd);
                    modified = true;
                }
            }
        }

        if (!modified) {
            // Last resort: try simple find-and-replace anywhere in the request
            if (origVal != null && !origVal.isEmpty() && reqStr.contains(origVal)) {
                reqStr = reqStr.replaceFirst(java.util.regex.Pattern.quote(origVal),
                        java.util.regex.Matcher.quoteReplacement(payload));
                modified = true;
            }
        }

        return modified ? reqStr.getBytes(StandardCharsets.ISO_8859_1) : null;
    }

    /** Update Content-Length header to match new body size */
    private String updateContentLength(String request, int bodyLength) {
        return request.replaceFirst("(?i)content-length:\\s*\\d+",
                "Content-Length: " + bodyLength);
    }

    /** Format a test result for display and for sending to AI */
    private String formatTestResult(int num, TestCase tc, int statusCode, long elapsed, int bodyLen, String bodySnippet) {
        StringBuilder sb = new StringBuilder();
        sb.append("  Test #").append(num).append(": ").append(tc.desc()).append("\n");
        sb.append("    Param: ").append(tc.param()).append(" [").append(tc.where()).append("]\n");
        sb.append("    Payload: ").append(tc.payload()).append("\n");
        if (statusCode >= 0) {
            sb.append("    Status: ").append(statusCode);
            sb.append(" | Time: ").append(elapsed).append("ms");
            sb.append(" | Size: ").append(bodyLen).append(" bytes\n");
            if (bodySnippet != null && !bodySnippet.isEmpty() && !bodySnippet.startsWith("[")) {
                // Show first 200 chars of body
                String snippet = bodySnippet.length() > 200 ? bodySnippet.substring(0, 200) + "..." : bodySnippet;
                sb.append("    Response: ").append(snippet.replace("\n", " ").replace("\r", ""));
            }
        } else {
            sb.append("    ").append(bodySnippet);
        }
        return sb.toString();
    }

    // ── Stop ───────────────────────────────────────────────────────

    private void stopExecution() {
        cancelled = true;
        if (currentWorker != null && !currentWorker.isDone()) {
            currentWorker.cancel(true);
        }
        setExecuting(false);
    }

    private void setExecuting(boolean executing) {
        executeBtn.setEnabled(!executing);
        stopBtn.setEnabled(executing);
        progressBar.setVisible(executing);
        if (executing) {
            progressBar.setIndeterminate(true);
            progressBar.setString("Working...");
        }
        statusLabel.setText(executing ? "Executing..." : "Ready");
    }

    // ── Formatted rendering ────────────────────────────────────────

    private void renderFormattedResult(String text) {
        if (text == null || text.isEmpty()) return;
        String[] lines = text.split("\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("###")) {
                appendStyled("  " + trimmed.substring(3).trim() + "\n", new Color(180, 140, 255), true);
            } else if (trimmed.startsWith("##")) {
                appendStyled(trimmed.substring(2).trim() + "\n", new Color(100, 200, 255), true);
            } else if (trimmed.startsWith("#")) {
                appendStyled(trimmed.substring(1).trim() + "\n", new Color(255, 200, 80), true);
            } else if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
                appendStyled("  \u2022 ", new Color(100, 200, 255), false);
                renderInline(trimmed.substring(2));
                appendStyled("\n", theme.fg, false);
            } else {
                renderInline(line);
                appendStyled("\n", theme.fg, false);
            }
        }
    }

    private void renderInline(String text) {
        int i = 0;
        while (i < text.length()) {
            if (i < text.length() - 3 && text.charAt(i) == '*' && text.charAt(i + 1) == '*') {
                int end = text.indexOf("**", i + 2);
                if (end > i + 2) {
                    String bold = text.substring(i + 2, end);
                    Color c = getSeverityColor(bold);
                    appendStyled(bold, c, true);
                    i = end + 2;
                    continue;
                }
            }
            if (text.charAt(i) == '`') {
                int end = text.indexOf('`', i + 1);
                if (end > i + 1) {
                    appendStyled(text.substring(i + 1, end),
                            theme.isDark() ? new Color(220, 170, 100) : new Color(180, 100, 40), false);
                    i = end + 1;
                    continue;
                }
            }
            int next = text.length();
            for (int j = i + 1; j < text.length(); j++) {
                if (text.charAt(j) == '*' || text.charAt(j) == '`') { next = j; break; }
            }
            appendStyled(text.substring(i, next), theme.fg, false);
            i = next;
        }
    }

    private Color getSeverityColor(String text) {
        String lower = text.toLowerCase();
        if (lower.contains("critical")) return new Color(255, 50, 50);
        if (lower.contains("high")) return new Color(255, 120, 50);
        if (lower.contains("medium")) return new Color(255, 200, 50);
        if (lower.contains("low")) return new Color(100, 200, 100);
        if (lower.contains("confirmed")) return new Color(255, 50, 50);
        if (lower.contains("reflected")) return new Color(255, 80, 80);
        return theme.isDark() ? new Color(240, 240, 240) : new Color(30, 30, 30);
    }

    // ── API Key Dialog ─────────────────────────────────────────────

    private void showApiKeyDialog() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 6, 4, 6);
        g.fill = GridBagConstraints.HORIZONTAL;

        JTextField[] keyFields = new JTextField[Provider.values().length];
        JTextField[] modelFields = new JTextField[Provider.values().length];

        int row = 0;
        for (Provider p : Provider.values()) {
            g.gridx = 0; g.gridy = row; g.weightx = 0;
            JLabel label = new JLabel(p.displayName + ":");
            label.setFont(theme.editorFont.deriveFont(Font.BOLD, 12f));
            panel.add(label, g);

            g.gridx = 1; g.weightx = 1.0;
            JPasswordField keyField = new JPasswordField(AiConfig.getApiKey(p), 30);
            keyField.setFont(theme.editorFont.deriveFont(11f));
            keyField.setEchoChar('\u2022');
            keyFields[p.ordinal()] = keyField;
            panel.add(keyField, g);

            g.gridx = 2; g.weightx = 0;
            JCheckBox showKey = new JCheckBox("Show");
            showKey.setFont(theme.editorFont.deriveFont(10f));
            final JPasswordField kf = keyField;
            showKey.addActionListener(e -> kf.setEchoChar(showKey.isSelected() ? (char) 0 : '\u2022'));
            panel.add(showKey, g);
            row++;

            g.gridx = 0; g.gridy = row; g.weightx = 0;
            JLabel modelLabel = new JLabel("  Model:");
            modelLabel.setFont(theme.editorFont.deriveFont(Font.ITALIC, 11f));
            modelLabel.setForeground(theme.bodyHint);
            panel.add(modelLabel, g);

            g.gridx = 1; g.weightx = 1.0;
            JTextField modelField = new JTextField(AiConfig.getModel(p), 30);
            modelField.setFont(theme.editorFont.deriveFont(11f));
            modelFields[p.ordinal()] = modelField;
            panel.add(modelField, g);

            g.gridx = 2; g.weightx = 0;
            JLabel defLabel = new JLabel("default: " + p.defaultModel);
            defLabel.setFont(theme.editorFont.deriveFont(Font.ITALIC, 9f));
            defLabel.setForeground(theme.bodyHint);
            panel.add(defLabel, g);
            row++;

            g.gridx = 0; g.gridy = row; g.gridwidth = 3;
            panel.add(new JSeparator(), g);
            g.gridwidth = 1;
            row++;
        }

        g.gridx = 0; g.gridy = row; g.gridwidth = 3;
        JLabel note = new JLabel("API keys are stored globally (user preferences) — not in the project file.");
        note.setFont(theme.editorFont.deriveFont(Font.ITALIC, 10f));
        note.setForeground(theme.bodyHint);
        panel.add(note, g);

        int result = JOptionPane.showConfirmDialog(this, panel,
                "AI Provider Settings", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            for (Provider p : Provider.values()) {
                String key = new String(((JPasswordField) keyFields[p.ordinal()]).getPassword()).trim();
                AiConfig.setApiKey(p, key);
                String model = modelFields[p.ordinal()].getText().trim();
                AiConfig.setModel(p, model);
            }
            statusLabel.setText("Settings saved");
        }
    }

    // ── Prompt Manager Dialog ──────────────────────────────────────

    private void showPromptManagerDialog() {
        Map<String, String> prompts = AiConfig.getAllPrompts();
        String[] cols = {"Prompt Name", "Preview"};
        DefaultTableModel model = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return c == 0; }
        };
        for (Map.Entry<String, String> e : prompts.entrySet()) {
            String preview = e.getValue().replace('\n', ' ');
            if (preview.length() > 80) preview = preview.substring(0, 80) + "...";
            model.addRow(new Object[]{e.getKey(), preview});
        }

        JTable table = new JTable(model);
        table.setFont(theme.editorFont.deriveFont(11f));
        table.setRowHeight(24);
        table.setSelectionBackground(new Color(50, 80, 120));
        table.setSelectionForeground(Color.WHITE);
        table.getColumnModel().getColumn(0).setPreferredWidth(150);
        table.getColumnModel().getColumn(1).setPreferredWidth(400);

        JScrollPane tableSp = new JScrollPane(table);
        tableSp.setPreferredSize(new Dimension(600, 200));

        JTextArea contentArea = new JTextArea(8, 50);
        contentArea.setFont(theme.editorFont.deriveFont(12f));
        contentArea.setLineWrap(true);
        contentArea.setWrapStyleWord(true);

        JScrollPane contentSp = new JScrollPane(contentArea);
        contentSp.setPreferredSize(new Dimension(600, 200));
        contentSp.setBorder(BorderFactory.createTitledBorder("Prompt Content (use {{request}} and {{response}})"));

        Map<String, String> mutablePrompts = new LinkedHashMap<>(prompts);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int row = table.getSelectedRow();
            if (row >= 0) {
                String name = (String) model.getValueAt(row, 0);
                contentArea.setText(mutablePrompts.getOrDefault(name, ""));
            }
        });

        contentArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { save(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { save(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) {}
            void save() {
                int row = table.getSelectedRow();
                if (row >= 0) {
                    String name = (String) model.getValueAt(row, 0);
                    if (name != null && !name.isBlank()) {
                        mutablePrompts.put(name, contentArea.getText());
                        String preview = contentArea.getText().replace('\n', ' ');
                        if (preview.length() > 80) preview = preview.substring(0, 80) + "...";
                        model.setValueAt(preview, row, 1);
                    }
                }
            }
        });

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));

        JButton addBtn = new JButton("+ New");
        addBtn.addActionListener(e -> {
            String name = JOptionPane.showInputDialog(this, "Prompt name:", "New Prompt", JOptionPane.QUESTION_MESSAGE);
            if (name != null && !name.trim().isEmpty()) {
                name = name.trim();
                mutablePrompts.put(name, "");
                model.addRow(new Object[]{name, ""});
                table.setRowSelectionInterval(model.getRowCount() - 1, model.getRowCount() - 1);
                contentArea.setText("");
                contentArea.requestFocus();
            }
        });

        JButton delBtn = new JButton("- Delete");
        delBtn.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0) {
                String name = (String) model.getValueAt(row, 0);
                if (JOptionPane.showConfirmDialog(this, "Delete prompt '" + name + "'?",
                        "Confirm", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                    mutablePrompts.remove(name);
                    model.removeRow(row);
                    contentArea.setText("");
                }
            }
        });

        JButton dupBtn = new JButton("Duplicate");
        dupBtn.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0) {
                String origName = (String) model.getValueAt(row, 0);
                String newName = origName + " (copy)";
                String content = mutablePrompts.getOrDefault(origName, "");
                mutablePrompts.put(newName, content);
                String preview = content.replace('\n', ' ');
                if (preview.length() > 80) preview = preview.substring(0, 80) + "...";
                model.addRow(new Object[]{newName, preview});
            }
        });

        btnPanel.add(addBtn);
        btnPanel.add(delBtn);
        btnPanel.add(dupBtn);

        JLabel hint = new JLabel("Use {{request}} and {{response}} placeholders. Saved in Burp project.");
        hint.setFont(theme.editorFont.deriveFont(Font.ITALIC, 10f));
        hint.setForeground(theme.bodyHint);

        JPanel mainPanel = new JPanel(new BorderLayout(0, 4));
        mainPanel.add(tableSp, BorderLayout.NORTH);
        mainPanel.add(contentSp, BorderLayout.CENTER);
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(btnPanel, BorderLayout.NORTH);
        bottomPanel.add(hint, BorderLayout.SOUTH);
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        if (model.getRowCount() > 0) table.setRowSelectionInterval(0, 0);

        int result = JOptionPane.showConfirmDialog(this, mainPanel,
                "AI Prompt Templates", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            Map<String, String> finalPrompts = new LinkedHashMap<>();
            for (int r = 0; r < model.getRowCount(); r++) {
                String name = (String) model.getValueAt(r, 0);
                if (name != null && !name.trim().isEmpty()) {
                    finalPrompts.put(name.trim(), mutablePrompts.getOrDefault(name, ""));
                }
            }
            AiConfig.replaceAllPrompts(finalPrompts);
            statusLabel.setText("Prompts saved");
        }
    }

    private void showNewPromptDialog() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        JTextField nameField = new JTextField(20);
        nameField.setFont(theme.editorFont.deriveFont(12f));
        JTextArea contentArea = new JTextArea(10, 50);
        contentArea.setFont(theme.editorFont.deriveFont(12f));
        contentArea.setLineWrap(true);
        contentArea.setWrapStyleWord(true);
        contentArea.setText("Analyze the following HTTP request for vulnerabilities.\n\n{{request}}");

        JPanel topPanel = new JPanel(new BorderLayout(4, 0));
        topPanel.add(new JLabel("Name: "), BorderLayout.WEST);
        topPanel.add(nameField, BorderLayout.CENTER);

        JScrollPane sp = new JScrollPane(contentArea);
        sp.setBorder(BorderFactory.createTitledBorder("Prompt Content (use {{request}} / {{response}})"));

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(sp, BorderLayout.CENTER);

        int result = JOptionPane.showConfirmDialog(this, panel,
                "New AI Prompt", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            String name = nameField.getText().trim();
            if (!name.isEmpty()) {
                AiConfig.setPrompt(name, contentArea.getText());
                statusLabel.setText("Prompt '" + name + "' saved");
            }
        }
    }

    // ── Helpers ────────────────────────────────────────────────────

    private void refreshPromptCombo() {
        promptCombo.removeAllItems();
        for (String name : AiConfig.getAllPrompts().keySet()) {
            promptCombo.addItem(name);
        }
    }

    private void showError(String message) {
        appendStyled("\u274C " + message + "\n", new Color(255, 80, 80), true);
    }

    private void appendStyled(String text, Color fg, boolean bold) {
        try {
            StyledDocument doc = resultsPane.getStyledDocument();
            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setForeground(attrs, fg);
            StyleConstants.setBold(attrs, bold);
            StyleConstants.setFontFamily(attrs, theme.editorFont.getFamily());
            StyleConstants.setFontSize(attrs, 12);
            doc.insertString(doc.getLength(), text, attrs);
        } catch (Exception ignored) {}
    }

    private JButton smallBtn(String text, String tooltip) {
        JButton btn = new JButton(text);
        btn.setFont(theme.editorFont.deriveFont(Font.BOLD, 12f));
        btn.setToolTipText(tooltip);
        btn.setMargin(new Insets(1, 4, 1, 4));
        btn.setFocusPainted(false);
        return btn;
    }

    private JSeparator createSep() {
        JSeparator sep = new JSeparator(SwingConstants.VERTICAL);
        sep.setPreferredSize(new Dimension(1, 20));
        return sep;
    }

    /** Release resources — called when the parent editor is disposed. */
    public void cleanup() {
        stopExecution();
        requestSupplier = null;
        responseSupplier = null;
        requestBytesSupplier = null;
        serviceSupplier = null;
        burpApi = null;
    }

    private static String repeat(String s, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) sb.append(s);
        return sb.toString();
    }
}
