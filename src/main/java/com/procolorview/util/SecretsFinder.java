package com.procolorview.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Escanea texto HTTP (headers + body) en busca de secretos expuestos:
 * API keys, tokens, passwords, private keys, connection strings, etc.
 *
 * Retorna resultados como lista de Match(type, value, line).
 */
public final class SecretsFinder {

    private SecretsFinder() {}

    public record Match(String type, String value, int line) {}

    // ── Pattern registry ───────────────────────────────────────────

    private static final Map<String, Pattern> PATTERNS = new LinkedHashMap<>();

    static {
        // ── AWS ──
        PATTERNS.put("AWS Access Key",
                Pattern.compile("AKIA[0-9A-Z]{16}"));
        PATTERNS.put("AWS Secret Key",
                Pattern.compile("(?i)(?:aws_secret_access_key|aws_secret)\\s*[=:]\\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"));
        PATTERNS.put("AWS ARN",
                Pattern.compile("arn:aws:[a-z0-9*-]+:[a-z0-9*-]*:\\d{12}:[a-zA-Z0-9/_-]+"));

        // ── Google ──
        PATTERNS.put("Google API Key",
                Pattern.compile("AIza[0-9A-Za-z_-]{35}"));
        PATTERNS.put("Google OAuth",
                Pattern.compile("\\d+-[a-z0-9_]{32}\\.apps\\.googleusercontent\\.com"));
        PATTERNS.put("GCP Service Account",
                Pattern.compile("\"type\"\\s*:\\s*\"service_account\""));

        // ── GitHub ──
        PATTERNS.put("GitHub Token (ghp)",
                Pattern.compile("ghp_[A-Za-z0-9]{36}"));
        PATTERNS.put("GitHub Token (gho)",
                Pattern.compile("gho_[A-Za-z0-9]{36}"));
        PATTERNS.put("GitHub Token (ghu)",
                Pattern.compile("ghu_[A-Za-z0-9]{36}"));
        PATTERNS.put("GitHub Token (ghs)",
                Pattern.compile("ghs_[A-Za-z0-9]{36}"));
        PATTERNS.put("GitHub Token (ghr)",
                Pattern.compile("ghr_[A-Za-z0-9]{36}"));
        PATTERNS.put("GitHub Classic Token",
                Pattern.compile("ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"));

        // ── Slack ──
        PATTERNS.put("Slack Token",
                Pattern.compile("xox[bporas]-[0-9A-Za-z-]{10,250}"));
        PATTERNS.put("Slack Webhook",
                Pattern.compile("https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"));

        // ── Stripe ──
        PATTERNS.put("Stripe Secret Key",
                Pattern.compile("sk_live_[0-9a-zA-Z]{24,}"));
        PATTERNS.put("Stripe Publishable Key",
                Pattern.compile("pk_live_[0-9a-zA-Z]{24,}"));
        PATTERNS.put("Stripe Test Key",
                Pattern.compile("[sr]k_test_[0-9a-zA-Z]{24,}"));

        // ── Twilio ──
        PATTERNS.put("Twilio API Key",
                Pattern.compile("SK[0-9a-fA-F]{32}"));
        PATTERNS.put("Twilio Account SID",
                Pattern.compile("AC[a-z0-9]{32}"));

        // ── Heroku ──
        PATTERNS.put("Heroku API Key",
                Pattern.compile("(?i)heroku[a-z0-9_ .\\-]*[=:]\\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]?"));

        // ── Azure ──
        PATTERNS.put("Azure Storage Key",
                Pattern.compile("(?i)(?:AccountKey|azure_storage_key)\\s*[=:]\\s*['\"]?[A-Za-z0-9+/=]{44,}['\"]?"));
        PATTERNS.put("Azure Connection String",
                Pattern.compile("DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+;?"));

        // ── Firebase ──
        PATTERNS.put("Firebase URL",
                Pattern.compile("https://[a-z0-9-]+\\.firebaseio\\.com"));
        PATTERNS.put("Firebase Key",
                Pattern.compile("AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}")); // FCM server key

        // ── SendGrid / Mailgun / Mailchimp ──
        PATTERNS.put("SendGrid API Key",
                Pattern.compile("SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}"));
        PATTERNS.put("Mailgun API Key",
                Pattern.compile("key-[0-9a-zA-Z]{32}"));
        PATTERNS.put("Mailchimp API Key",
                Pattern.compile("[0-9a-f]{32}-us\\d{1,2}"));

        // ── Generic tokens ──
        PATTERNS.put("Bearer Token",
                Pattern.compile("(?i)Bearer\\s+[A-Za-z0-9_\\-.~+/]+=*"));
        PATTERNS.put("Basic Auth",
                Pattern.compile("(?i)Basic\\s+[A-Za-z0-9+/]{10,}={0,2}"));
        PATTERNS.put("Authorization Header",
                Pattern.compile("(?i)Authorization:\\s*\\S+\\s+\\S+"));

        // ── Private keys ──
        PATTERNS.put("RSA Private Key",
                Pattern.compile("-----BEGIN (?:RSA )?PRIVATE KEY-----"));
        PATTERNS.put("SSH Private Key",
                Pattern.compile("-----BEGIN OPENSSH PRIVATE KEY-----"));
        PATTERNS.put("PGP Private Key",
                Pattern.compile("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        PATTERNS.put("EC Private Key",
                Pattern.compile("-----BEGIN EC PRIVATE KEY-----"));

        // ── Generic password/secret patterns ──
        PATTERNS.put("Password Field",
                Pattern.compile("(?i)(?:password|passwd|pwd|pass)\\s*[=:]\\s*['\"]?[^\\s'\"]{4,}['\"]?"));
        PATTERNS.put("Secret/Token Field",
                Pattern.compile("(?i)(?:api_?key|api_?secret|secret_?key|access_?token|auth_?token|client_?secret)\\s*[=:]\\s*['\"]?[^\\s'\"]{8,}['\"]?"));

        // ── Connection strings ──
        PATTERNS.put("Database URL",
                Pattern.compile("(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp|mssql)://[^\\s'\"]+"));
        PATTERNS.put("JDBC Connection",
                Pattern.compile("jdbc:[a-z]+://[^\\s'\"]+"));
        PATTERNS.put("SMTP Credentials",
                Pattern.compile("(?i)smtp://[^\\s'\"]+"));

        // ── JWT (standalone, not part of Bearer) ──
        PATTERNS.put("JWT Token",
                Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"));

        // ── Private IPs ──
        PATTERNS.put("Private IPv4",
                Pattern.compile("(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})"));

        // ── Email Addresses ──
        PATTERNS.put("Email Address",
                Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"));

        // ── S3 Buckets ──
        PATTERNS.put("S3 Bucket",
                Pattern.compile("(?:https?://)?[a-zA-Z0-9.-]+\\.s3[a-zA-Z0-9.-]*\\.amazonaws\\.com|s3://[a-zA-Z0-9._-]+"));
    }

    // ── Public API ─────────────────────────────────────────────────

    /**
     * Escanea el texto completo y retorna todos los matches encontrados.
     * Cada match incluye tipo, valor y número de línea (1-based).
     */
    public static List<Match> scan(String text) {
        List<Match> results = new ArrayList<>();
        if (text == null || text.isEmpty()) return results;

        String[] lines = text.split("\n", -1);

        for (Map.Entry<String, Pattern> entry : PATTERNS.entrySet()) {
            String type = entry.getKey();
            Pattern pattern = entry.getValue();

            for (int i = 0; i < lines.length; i++) {
                Matcher m = pattern.matcher(lines[i]);
                while (m.find()) {
                    String val = m.group();
                    // Truncar valores largos para display
                    String display = val.length() > 120 ? val.substring(0, 117) + "..." : val;
                    results.add(new Match(type, display, i + 1));
                }
            }
        }

        return results;
    }

    /**
     * Formatea los resultados como texto legible (para el diálogo).
     */
    public static String format(List<Match> matches) {
        if (matches.isEmpty()) return "No secrets found.";

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Found %d potential secret(s):\n", matches.size()));
        sb.append("═".repeat(70)).append("\n\n");

        String lastType = "";
        for (Match m : matches) {
            if (!m.type().equals(lastType)) {
                if (!lastType.isEmpty()) sb.append("\n");
                sb.append("▸ ").append(m.type()).append("\n");
                sb.append("─".repeat(40)).append("\n");
                lastType = m.type();
            }
            sb.append(String.format("  Line %-5d │ %s\n", m.line(), m.value()));
        }

        return sb.toString();
    }

    /**
     * Formatea para copiar limpio (solo valores, uno por línea).
     */
    public static String formatRaw(List<Match> matches) {
        StringBuilder sb = new StringBuilder();
        for (Match m : matches) {
            sb.append(m.type()).append("\t").append(m.value()).append("\t").append("Line:").append(m.line()).append("\n");
        }
        return sb.toString();
    }
}
