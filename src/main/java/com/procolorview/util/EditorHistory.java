package com.procolorview.util;

import javax.swing.*;
import java.awt.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Editor History / Versioning for Pro Color View.
 *
 * Keeps snapshots of the editor content at key moments.
 * Max 50 entries to limit memory usage.
 */
public class EditorHistory {

    /** A single snapshot — mutable label for renaming */
    public static class Snapshot {
        private String label;
        private final String content;
        private final LocalDateTime timestamp;

        public Snapshot(String label, String content, LocalDateTime timestamp) {
            this.label = label;
            this.content = content;
            this.timestamp = timestamp;
        }

        public String label() { return label; }
        public String content() { return content; }
        public LocalDateTime timestamp() { return timestamp; }
        public void setLabel(String newLabel) { this.label = newLabel; }

        public String display() {
            return "[" + timestamp.format(DateTimeFormatter.ofPattern("HH:mm:ss")) + "] " + label
                    + " (" + content.length() + " chars)";
        }
    }

    private final List<Snapshot> history = new ArrayList<>();
    private static final int MAX_ENTRIES = 50;

    /** Save a snapshot with a label describing what happened */
    public void save(String label, String content) {
        if (content == null) return;
        // Don't save duplicate if content is identical to last snapshot
        if (!history.isEmpty()) {
            Snapshot last = history.get(history.size() - 1);
            if (last.content().equals(content)) return;
        }
        history.add(new Snapshot(label, content, LocalDateTime.now()));
        while (history.size() > MAX_ENTRIES) {
            history.remove(0);
        }
    }

    public List<Snapshot> getAll() { return new ArrayList<>(history); }
    public int size() { return history.size(); }
    public void clear() { history.clear(); }

    /**
     * Show the history browser dialog.
     * Returns the content of the selected snapshot to restore, or null if cancelled.
     */
    public String showBrowserDialog(Component parent, Color bg, Color fg, Font font) {
        if (history.isEmpty()) {
            JOptionPane.showMessageDialog(parent, "No history yet.\n\n"
                    + "Snapshots are saved automatically when you:\n"
                    + "  \u2022 Load a new request/response\n"
                    + "  \u2022 Apply template variables\n"
                    + "  \u2022 Replace all\n"
                    + "  \u2022 Toggle Pretty/Minify\n"
                    + "  \u2022 Manually save a snapshot",
                    "Editor History", JOptionPane.INFORMATION_MESSAGE);
            return null;
        }

        // List model (newest first)
        DefaultListModel<Snapshot> listModel = new DefaultListModel<>();
        for (int i = history.size() - 1; i >= 0; i--) {
            listModel.addElement(history.get(i));
        }

        JList<Snapshot> list = new JList<>(listModel);
        list.setFont(font);
        list.setBackground(bg);
        list.setForeground(fg);
        list.setSelectionBackground(new Color(50, 80, 120));
        list.setSelectionForeground(Color.WHITE);
        list.setFixedCellHeight(22);
        list.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> l, Object v, int i, boolean sel, boolean foc) {
                super.getListCellRendererComponent(l, v, i, sel, foc);
                if (v instanceof Snapshot s) {
                    setText(s.display());
                    setFont(font);
                    if (!sel) { setBackground(bg); setForeground(fg); }
                }
                return this;
            }
        });
        list.setSelectedIndex(0);

        // Preview pane
        JTextArea preview = new JTextArea();
        preview.setFont(font);
        preview.setEditable(false);
        preview.setBackground(bg);
        preview.setForeground(fg);
        preview.setLineWrap(true);
        preview.setWrapStyleWord(true);

        // Update preview on selection
        list.addListSelectionListener(e -> {
            Snapshot sel = list.getSelectedValue();
            if (sel != null) {
                String text = sel.content();
                if (text.length() > 2000) {
                    text = text.substring(0, 2000) + "\n\n... (" + sel.content().length() + " chars total)";
                }
                preview.setText(text);
                preview.setCaretPosition(0);
            }
        });
        // Initial preview
        if (!history.isEmpty()) {
            Snapshot first = listModel.get(0);
            String text = first.content();
            if (text.length() > 2000) text = text.substring(0, 2000) + "\n... (" + first.content().length() + " chars)";
            preview.setText(text);
            preview.setCaretPosition(0);
        }

        JScrollPane listScroll = new JScrollPane(list);
        listScroll.setPreferredSize(new Dimension(350, 300));
        JScrollPane previewScroll = new JScrollPane(preview);
        previewScroll.setPreferredSize(new Dimension(400, 300));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, listScroll, previewScroll);
        split.setDividerLocation(350);
        split.setResizeWeight(0.4);

        JLabel info = new JLabel(history.size() + " snapshot(s) — select one and click Restore");
        info.setForeground(new Color(140, 140, 160));
        info.setFont(font.deriveFont(11f));

        // Buttons
        JButton renameBtn = new JButton("Rename");
        renameBtn.setToolTipText("Rename the selected snapshot");
        renameBtn.addActionListener(e -> {
            Snapshot sel = list.getSelectedValue();
            if (sel == null) return;
            String newName = JOptionPane.showInputDialog(parent, "New name:", sel.label());
            if (newName != null && !newName.isBlank()) {
                sel.setLabel(newName.strip());
                // Refresh the list display
                int idx = list.getSelectedIndex();
                listModel.set(idx, sel);
                list.repaint();
            }
        });

        JButton deleteBtn = new JButton("Delete");
        deleteBtn.addActionListener(e -> {
            Snapshot sel = list.getSelectedValue();
            if (sel != null) {
                history.remove(sel);
                listModel.removeElement(sel);
                info.setText(history.size() + " snapshot(s)");
            }
        });

        JButton clearBtn = new JButton("Clear All");
        clearBtn.addActionListener(e -> {
            history.clear();
            listModel.clear();
            preview.setText("");
            info.setText("0 snapshot(s)");
        });

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        btnPanel.add(renameBtn);
        btnPanel.add(deleteBtn);
        btnPanel.add(clearBtn);

        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.add(info, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        panel.add(btnPanel, BorderLayout.SOUTH);

        // Also allow double-click on list to rename
        list.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    renameBtn.doClick();
                }
            }
        });

        int result = JOptionPane.showOptionDialog(parent, panel, "Editor History",
                JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null,
                new String[]{"Restore Selected", "Cancel"}, "Restore Selected");

        if (result == 0) {
            Snapshot sel = list.getSelectedValue();
            return sel != null ? sel.content() : null;
        }
        return null;
    }
}
