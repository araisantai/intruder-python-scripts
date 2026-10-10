package io.github.intruderrequestsscript;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

final class BurpStyleConfigDialog {
    private final int positions;
    private final JComboBox<AttackMode> mode = new JComboBox<>(AttackMode.values());
    private final JTabbedPane payloadSets = new JTabbedPane();
    private final DefaultListModel<ScriptConfiguration.ProcessingRule> rules = new DefaultListModel<>();
    private final JSpinner concurrency = new JSpinner(new SpinnerNumberModel(10, 1, 999, 1));
    private final JSpinner delay = new JSpinner(new SpinnerNumberModel(0, 0, 3_600_000, 50));
    private final JSpinner retries = new JSpinner(new SpinnerNumberModel(0, 0, 100, 1));
    private final JSpinner timeout = new JSpinner(new SpinnerNumberModel(30, 1, 3600, 1));
    private final JCheckBox redirects = new JCheckBox("Follow redirections", false);
    private final JCheckBox verifyTls = new JCheckBox("Verify TLS certificates", false);

    private BurpStyleConfigDialog(int positions) {
        this.positions = positions;
        mode.addActionListener(e -> rebuildPayloadSets());
        rebuildPayloadSets();
    }

    static ScriptConfiguration show(Component parent, int positions) {
        BurpStyleConfigDialog dialog = new BurpStyleConfigDialog(positions);
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Positions", dialog.positionsPanel());
        tabs.addTab("Payloads", dialog.payloadPanel());
        tabs.addTab("Resource pool", dialog.resourcePanel());
        tabs.addTab("Settings", dialog.settingsPanel());
        tabs.setPreferredSize(new Dimension(720, 520));
        int result = JOptionPane.showConfirmDialog(parent, tabs, "Intruder attack configuration",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        return result == JOptionPane.OK_OPTION ? dialog.configuration() : null;
    }

    private JPanel positionsPanel() {
        JPanel panel = verticalPanel();
        panel.add(section("Attack type"));
        panel.add(labeled("Attack type:", mode));
        panel.add(Box.createVerticalStrut(12));
        panel.add(new JLabel(positions + " payload position" + (positions == 1 ? "" : "s") + " detected in the request."));
        panel.add(Box.createVerticalGlue());
        return panel;
    }

    private JPanel payloadPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 10));
        panel.setBorder(new EmptyBorder(12, 12, 12, 12));
        JPanel top = new JPanel(new BorderLayout());
        top.add(section("Payload sets"), BorderLayout.NORTH);
        top.add(payloadSets, BorderLayout.CENTER);
        panel.add(top, BorderLayout.CENTER);
        panel.add(processingPanel(), BorderLayout.SOUTH);
        return panel;
    }

    private JPanel processingPanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(BorderFactory.createTitledBorder("Payload processing"));
        JList<ScriptConfiguration.ProcessingRule> list = new JList<>(rules);
        list.setVisibleRowCount(5);
        JPanel buttons = new JPanel(new GridLayout(0, 1, 4, 4));
        JButton add = new JButton("Add");
        JButton remove = new JButton("Remove");
        add.addActionListener(e -> addRule(panel));
        remove.addActionListener(e -> {
            int selected = list.getSelectedIndex();
            if (selected >= 0) rules.remove(selected);
        });
        buttons.add(add);
        buttons.add(remove);
        panel.add(new JScrollPane(list), BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.EAST);
        return panel;
    }

    private void addRule(Component parent) {
        JComboBox<ScriptConfiguration.RuleType> type = new JComboBox<>(ScriptConfiguration.RuleType.values());
        JTextField first = new JTextField(24);
        JTextField second = new JTextField(24);
        JPanel fields = verticalPanel();
        fields.add(labeled("Rule type:", type));
        fields.add(labeled("Value / match:", first));
        fields.add(labeled("Replacement:", second));
        if (JOptionPane.showConfirmDialog(parent, fields, "Add payload processing rule",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) == JOptionPane.OK_OPTION) {
            rules.addElement(new ScriptConfiguration.ProcessingRule(
                    (ScriptConfiguration.RuleType) type.getSelectedItem(), first.getText(), second.getText()));
        }
    }

    private JPanel resourcePanel() {
        JPanel panel = verticalPanel();
        panel.add(section("Resource pool"));
        panel.add(labeled("Maximum concurrent requests:", concurrency));
        panel.add(labeled("Delay between requests (ms):", delay));
        panel.add(labeled("Maximum retries:", retries));
        panel.add(Box.createVerticalGlue());
        return panel;
    }

    private JPanel settingsPanel() {
        JPanel panel = verticalPanel();
        panel.add(section("Request engine"));
        panel.add(labeled("Request timeout (seconds):", timeout));
        panel.add(redirects);
        panel.add(verifyTls);
        panel.add(Box.createVerticalGlue());
        return panel;
    }

    private void rebuildPayloadSets() {
        List<String> contents = new ArrayList<>();
        for (int i = 0; i < payloadSets.getTabCount(); i++) {
            contents.add(textAreaAt(i).getText());
        }
        payloadSets.removeAll();
        AttackMode selected = (AttackMode) mode.getSelectedItem();
        int count = selected == AttackMode.SNIPER || selected == AttackMode.BATTERING_RAM ? 1 : positions;
        for (int i = 0; i < count; i++) {
            JTextArea area = new JTextArea(i < contents.size() ? contents.get(i) : "", 10, 55);
            area.setLineWrap(false);
            area.setToolTipText("One payload per line");
            payloadSets.addTab("Payload set " + (i + 1), new JScrollPane(area));
        }
    }

    private ScriptConfiguration configuration() {
        List<List<String>> sets = new ArrayList<>();
        for (int i = 0; i < payloadSets.getTabCount(); i++) {
            sets.add(textAreaAt(i).getText().replace("\r\n", "\n").lines().filter(line -> !line.isEmpty()).toList());
        }
        return new ScriptConfiguration((AttackMode) mode.getSelectedItem(), List.copyOf(sets),
                java.util.Collections.list(rules.elements()), (int) concurrency.getValue(),
                ((Number) delay.getValue()).longValue(), (int) retries.getValue(),
                (int) timeout.getValue(), redirects.isSelected(), verifyTls.isSelected());
    }

    private JTextArea textAreaAt(int index) {
        JScrollPane scroll = (JScrollPane) payloadSets.getComponentAt(index);
        return (JTextArea) scroll.getViewport().getView();
    }

    private static JPanel verticalPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(12, 12, 12, 12));
        return panel;
    }

    private static JLabel section(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, label.getFont().getSize2D() + 2));
        label.setBorder(new EmptyBorder(0, 0, 8, 0));
        return label;
    }

    private static JPanel labeled(String text, JComponent component) {
        JPanel row = new JPanel(new BorderLayout(10, 0));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 34));
        row.add(new JLabel(text), BorderLayout.WEST);
        row.add(component, BorderLayout.CENTER);
        return row;
    }
}
