package com.procolorview.ai;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Manages AI provider configuration (API keys, models) and prompt templates.
 * All data is persisted in the Burp project file via Montoya Persistence API.
 */
public final class AiConfig {

    private AiConfig() {}

    // ── Provider enum ──────────────────────────────────────────────

    public enum Provider {
        OPENAI("OpenAI (ChatGPT)", "gpt-4o-mini",
                "https://api.openai.com/v1/chat/completions"),
        ANTHROPIC("Anthropic (Claude)", "claude-sonnet-4-20250514",
                "https://api.anthropic.com/v1/messages"),
        GEMINI("Google Gemini", "gemini-2.0-flash",
                "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent"),
        OPENROUTER("OpenRouter", "openai/gpt-4o-mini",
                "https://openrouter.ai/api/v1/chat/completions");

        public final String displayName;
        public final String defaultModel;
        public final String endpoint;

        Provider(String displayName, String defaultModel, String endpoint) {
            this.displayName = displayName;
            this.defaultModel = defaultModel;
            this.endpoint = endpoint;
        }

        @Override public String toString() { return displayName; }
    }

    // ── Persistence keys ───────────────────────────────────────────

    private static final String KEY_PREFIX     = "pcv_ai_key_";
    private static final String MODEL_PREFIX   = "pcv_ai_model_";
    private static final String PROMPT_PREFIX  = "pcv_ai_prompt_";
    private static final String PROMPT_ORDER   = "pcv_ai_prompt__order_";
    private static final String SELECTED_PROV  = "pcv_ai_selected_provider";

    // ── In-memory state ────────────────────────────────────────────

    private static MontoyaApi burpApi;

    /** API keys: provider name → key */
    private static final Map<String, String> API_KEYS = new LinkedHashMap<>();
    /** Model overrides: provider name → model string */
    private static final Map<String, String> MODELS = new LinkedHashMap<>();
    /** Prompt templates: name → content */
    private static final Map<String, String> PROMPTS = new LinkedHashMap<>();
    /** Currently selected provider */
    private static Provider selectedProvider = Provider.OPENAI;

    // ── Init ───────────────────────────────────────────────────────

    /** Must be called once from ProColorExtension.initialize() */
    public static void init(MontoyaApi api) {
        burpApi = api;
        loadFromProject();
    }

    private static void loadFromProject() {
        if (burpApi == null) return;
        try {
            PersistedObject data = burpApi.persistence().extensionData();

            // Load API keys and models
            for (Provider p : Provider.values()) {
                String key = data.getString(KEY_PREFIX + p.name());
                if (key != null) API_KEYS.put(p.name(), key);
                String model = data.getString(MODEL_PREFIX + p.name());
                if (model != null) MODELS.put(p.name(), model);
            }

            // Load selected provider
            String selProv = data.getString(SELECTED_PROV);
            if (selProv != null) {
                try { selectedProvider = Provider.valueOf(selProv); }
                catch (IllegalArgumentException ignored) {}
            }

            // Load prompts with ordering
            Map<String, String> allPrompts = new LinkedHashMap<>();
            for (String k : data.stringKeys()) {
                if (k.startsWith(PROMPT_PREFIX) && !k.equals(PROMPT_ORDER)) {
                    String name = k.substring(PROMPT_PREFIX.length());
                    String val = data.getString(k);
                    if (val != null) allPrompts.put(name, val);
                }
            }
            String order = data.getString(PROMPT_ORDER);
            if (order != null && !order.isEmpty()) {
                for (String name : order.split("\n")) {
                    if (allPrompts.containsKey(name)) {
                        PROMPTS.put(name, allPrompts.remove(name));
                    }
                }
            }
            PROMPTS.putAll(allPrompts);

            // Add default prompts if none exist
            if (PROMPTS.isEmpty()) addDefaultPrompts();

        } catch (Exception ignored) {}
    }

    private static void addDefaultPrompts() {
        PROMPTS.put("SQLi Detection", """
Analyze the following HTTP request for SQL Injection vulnerabilities.
Test each parameter (GET, POST, headers, cookies) for potential SQLi.
For each parameter:
1. Identify if it could be injectable
2. Suggest specific payloads to test
3. Explain the type of SQLi (Union, Blind, Error-based, Time-based)
4. Rate the likelihood (High/Medium/Low)

Provide a clear verdict at the end.

{{request}}""");

        PROMPTS.put("XSS Detection", """
Analyze the following HTTP request and response for Cross-Site Scripting (XSS) vulnerabilities.
Check:
1. All input parameters that are reflected in the response
2. Whether the output is HTML-encoded or sanitized
3. Context where the reflection occurs (HTML body, attribute, JavaScript, URL)
4. Suggest specific payloads that could bypass any detected filters
5. Rate the likelihood of successful XSS (High/Medium/Low)

Provide a clear verdict at the end.

Request:
{{request}}

Response:
{{response}}""");

        PROMPTS.put("SSRF Detection", """
Analyze the following HTTP request for Server-Side Request Forgery (SSRF) vulnerabilities.
Check:
1. Parameters that accept URLs, hostnames, IPs, or file paths
2. Potential for internal network scanning
3. Cloud metadata endpoint access (169.254.169.254, etc.)
4. DNS rebinding potential
5. Suggest specific payloads to test

{{request}}""");

        PROMPTS.put("Auth & Access Control", """
Analyze the following HTTP request for authentication and authorization vulnerabilities.
Check:
1. IDOR (Insecure Direct Object Reference) in parameters
2. Missing or weak authentication tokens
3. Privilege escalation potential
4. Session management issues
5. JWT vulnerabilities (if present)

{{request}}""");

        PROMPTS.put("Full Security Audit", """
Perform a comprehensive security audit of the following HTTP request/response pair.
Check for ALL common web vulnerabilities:
- SQL Injection
- Cross-Site Scripting (XSS)
- SSRF
- Command Injection
- Path Traversal / LFI
- IDOR
- Authentication/Authorization issues
- Information Disclosure
- Security Headers analysis
- CORS misconfiguration

For each finding, provide:
1. Vulnerability type
2. Affected parameter/header
3. Severity (Critical/High/Medium/Low/Info)
4. Suggested payload to confirm
5. Remediation recommendation

Request:
{{request}}

Response:
{{response}}""");

        savePrompts();
    }

    // ── Save helpers ───────────────────────────────────────────────

    private static void saveKeys() {
        if (burpApi == null) return;
        try {
            PersistedObject data = burpApi.persistence().extensionData();
            for (Provider p : Provider.values()) {
                String val = API_KEYS.get(p.name());
                if (val != null) data.setString(KEY_PREFIX + p.name(), val);
                else {
                    try { data.deleteString(KEY_PREFIX + p.name()); } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {}
    }

    private static void saveModels() {
        if (burpApi == null) return;
        try {
            PersistedObject data = burpApi.persistence().extensionData();
            for (Provider p : Provider.values()) {
                String val = MODELS.get(p.name());
                if (val != null) data.setString(MODEL_PREFIX + p.name(), val);
                else {
                    try { data.deleteString(MODEL_PREFIX + p.name()); } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {}
    }

    private static void saveSelectedProvider() {
        if (burpApi == null) return;
        try {
            burpApi.persistence().extensionData().setString(SELECTED_PROV, selectedProvider.name());
        } catch (Exception ignored) {}
    }

    private static void savePrompts() {
        if (burpApi == null) return;
        try {
            PersistedObject data = burpApi.persistence().extensionData();
            // Remove old prompts
            for (String k : new java.util.ArrayList<>(data.stringKeys())) {
                if (k.startsWith(PROMPT_PREFIX) || k.equals(PROMPT_ORDER)) {
                    data.deleteString(k);
                }
            }
            // Write current
            StringBuilder orderBuilder = new StringBuilder();
            for (Map.Entry<String, String> e : PROMPTS.entrySet()) {
                data.setString(PROMPT_PREFIX + e.getKey(), e.getValue());
                if (orderBuilder.length() > 0) orderBuilder.append("\n");
                orderBuilder.append(e.getKey());
            }
            data.setString(PROMPT_ORDER, orderBuilder.toString());
        } catch (Exception ignored) {}
    }

    // ── Public API ─────────────────────────────────────────────────

    // API Keys
    public static String getApiKey(Provider provider) {
        return API_KEYS.getOrDefault(provider.name(), "");
    }
    public static void setApiKey(Provider provider, String key) {
        if (key == null || key.isBlank()) API_KEYS.remove(provider.name());
        else API_KEYS.put(provider.name(), key.trim());
        saveKeys();
    }

    // Models
    public static String getModel(Provider provider) {
        return MODELS.getOrDefault(provider.name(), provider.defaultModel);
    }
    public static void setModel(Provider provider, String model) {
        if (model == null || model.isBlank()) MODELS.remove(provider.name());
        else MODELS.put(provider.name(), model.trim());
        saveModels();
    }

    // Selected provider
    public static Provider getSelectedProvider() { return selectedProvider; }
    public static void setSelectedProvider(Provider p) {
        selectedProvider = p;
        saveSelectedProvider();
    }

    // Prompts
    public static Map<String, String> getAllPrompts() { return new LinkedHashMap<>(PROMPTS); }
    public static String getPrompt(String name) { return PROMPTS.getOrDefault(name, ""); }
    public static void setPrompt(String name, String content) {
        PROMPTS.put(name, content);
        savePrompts();
    }
    public static void removePrompt(String name) {
        PROMPTS.remove(name);
        savePrompts();
    }
    public static void replaceAllPrompts(Map<String, String> newPrompts) {
        PROMPTS.clear();
        PROMPTS.putAll(newPrompts);
        savePrompts();
    }

    /** Check if the given provider has an API key configured */
    public static boolean hasApiKey(Provider provider) {
        String key = API_KEYS.get(provider.name());
        return key != null && !key.isBlank();
    }
}
