package com.procolorview.ai;

import burp.api.montoya.MontoyaApi;
import com.procolorview.ai.AiConfig.Provider;
import com.procolorview.theme.ProColorTheme;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Suite Tab for global AI provider settings.
 * Keys are stored in Burp user preferences (not the project file).
 */
public class AiSettingsTab extends JPanel {

    private final ProColorTheme theme;
    private final JPasswordField[] keyFields  = new JPasswordField[Provider.values().length];
    @SuppressWarnings("unchecked")
    private final JComboBox<String>[] modelCombos = new JComboBox[Provider.values().length];
    private JLabel statusLabel;

    public AiSettingsTab(MontoyaApi api) {
        super(new BorderLayout());
        this.theme = ProColorTheme.fromBurp(api);
        setBackground(theme.bg);
        buildUI();
    }

    private void buildUI() {
        // ── Header ─────────────────────────────────────────────────────
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBackground(theme.bg);
        header.setBorder(new EmptyBorder(20, 24, 10, 24));

        JLabel title = new JLabel("Pro Color View — AI Provider Settings");
        title.setFont(theme.editorFont.deriveFont(Font.BOLD, 15f));
        title.setForeground(theme.fg);
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        header.add(title);

        header.add(Box.createVerticalStrut(6));

        JLabel subtitle = new JLabel(
                "API keys are stored globally in Burp user preferences — not included in project files. Safe to share projects with clients.");
        subtitle.setFont(theme.editorFont.deriveFont(Font.ITALIC, 11f));
        subtitle.setForeground(theme.bodyHint);
        subtitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        header.add(subtitle);

        // ── Provider fields ────────────────────────────────────────────
        JPanel fields = new JPanel(new GridBagLayout());
        fields.setBackground(theme.bg);
        fields.setBorder(new EmptyBorder(4, 24, 4, 24));

        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(3, 6, 3, 6);
        g.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;
        for (Provider p : Provider.values()) {
            // Provider label
            g.gridx = 0; g.gridy = row; g.gridwidth = 3; g.weightx = 1.0;
            JLabel provLabel = new JLabel(p.displayName);
            provLabel.setFont(theme.editorFont.deriveFont(Font.BOLD, 12f));
            provLabel.setForeground(theme.headerName);
            fields.add(provLabel, g);
            g.gridwidth = 1;
            row++;

            // API Key row
            g.gridx = 0; g.gridy = row; g.weightx = 0;
            JLabel keyLabel = new JLabel("  API Key:");
            keyLabel.setFont(theme.editorFont.deriveFont(11f));
            keyLabel.setForeground(theme.fg);
            fields.add(keyLabel, g);

            g.gridx = 1; g.weightx = 1.0;
            JPasswordField keyField = new JPasswordField(AiConfig.getApiKey(p), 40);
            keyField.setFont(theme.editorFont.deriveFont(11f));
            keyField.setEchoChar('\u2022');
            styleField(keyField);
            keyFields[p.ordinal()] = keyField;
            fields.add(keyField, g);

            g.gridx = 2; g.weightx = 0;
            JCheckBox showKey = new JCheckBox("Show");
            showKey.setFont(theme.editorFont.deriveFont(10f));
            showKey.setBackground(theme.bg);
            showKey.setForeground(theme.fg);
            final JPasswordField kf = keyField;
            showKey.addActionListener(e -> kf.setEchoChar(showKey.isSelected() ? (char) 0 : '\u2022'));
            fields.add(showKey, g);
            row++;

            // Model row
            g.gridx = 0; g.gridy = row; g.weightx = 0;
            JLabel modelLabel = new JLabel("  Model:");
            modelLabel.setFont(theme.editorFont.deriveFont(Font.ITALIC, 11f));
            modelLabel.setForeground(theme.bodyHint);
            fields.add(modelLabel, g);

            g.gridx = 1; g.weightx = 1.0;
            JComboBox<String> modelCombo = new JComboBox<>(p.models);
            modelCombo.setEditable(true);
            modelCombo.setSelectedItem(AiConfig.getModel(p));
            modelCombo.setFont(theme.editorFont.deriveFont(11f));
            styleField((JTextField) modelCombo.getEditor().getEditorComponent());
            modelCombos[p.ordinal()] = modelCombo;
            fields.add(modelCombo, g);

            g.gridx = 2; g.weightx = 0;
            JLabel defLabel = new JLabel("default: " + p.defaultModel);
            defLabel.setFont(theme.editorFont.deriveFont(Font.ITALIC, 9f));
            defLabel.setForeground(theme.bodyHint);
            fields.add(defLabel, g);
            row++;

            // Separator
            g.gridx = 0; g.gridy = row; g.gridwidth = 3; g.weightx = 1.0;
            g.insets = new Insets(6, 6, 6, 6);
            JSeparator sep = new JSeparator();
            sep.setForeground(theme.selection);
            fields.add(sep, g);
            g.gridwidth = 1;
            g.insets = new Insets(3, 6, 3, 6);
            row++;
        }

        // Vertical filler so fields don't stretch
        g.gridx = 0; g.gridy = row; g.gridwidth = 3; g.weightx = 1.0; g.weighty = 1.0;
        fields.add(Box.createVerticalGlue(), g);

        // ── Footer (Save + status) ─────────────────────────────────────
        JPanel footer = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        footer.setBackground(theme.bg);
        footer.setBorder(new EmptyBorder(10, 20, 20, 20));

        JButton saveBtn = new JButton("Save Settings");
        saveBtn.setFont(theme.editorFont.deriveFont(Font.BOLD, 12f));
        saveBtn.addActionListener(e -> saveSettings());
        footer.add(saveBtn);

        footer.add(Box.createHorizontalStrut(12));

        statusLabel = new JLabel("");
        statusLabel.setFont(theme.editorFont.deriveFont(Font.ITALIC, 11f));
        statusLabel.setForeground(new Color(80, 200, 120));
        footer.add(statusLabel);

        // ── Assembly ───────────────────────────────────────────────────
        add(header, BorderLayout.NORTH);
        JScrollPane scroll = new JScrollPane(fields,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(null);
        scroll.getViewport().setBackground(theme.bg);
        add(scroll, BorderLayout.CENTER);
        add(footer, BorderLayout.SOUTH);
    }

    private void styleField(JTextField field) {
        field.setBackground(theme.searchFieldBg);
        field.setForeground(theme.fg);
        field.setCaretColor(theme.caret);
        field.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(theme.selection, 1),
                new EmptyBorder(2, 5, 2, 5)));
    }

    private void saveSettings() {
        for (Provider p : Provider.values()) {
            String key = new String(keyFields[p.ordinal()].getPassword()).trim();
            AiConfig.setApiKey(p, key);
            String model = ((String) modelCombos[p.ordinal()].getEditor().getItem()).trim();
            AiConfig.setModel(p, model);
        }
        statusLabel.setText("Settings saved.");
        Timer timer = new Timer(3000, e -> statusLabel.setText(""));
        timer.setRepeats(false);
        timer.start();
    }

    /** Reload field values from AiConfig (e.g. after saving from the gear dialog). */
    public void refresh() {
        for (Provider p : Provider.values()) {
            keyFields[p.ordinal()].setText(AiConfig.getApiKey(p));
            modelCombos[p.ordinal()].setSelectedItem(AiConfig.getModel(p));
        }
    }
}
