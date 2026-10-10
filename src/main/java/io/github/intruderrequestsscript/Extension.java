package io.github.intruderrequestsscript;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;

public final class Extension implements BurpExtension {
    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Intruder Python Scripts");
        api.userInterface().registerContextMenuItemsProvider(new MenuProvider());
        api.logging().logToOutput("Intruder Python Scripts loaded. Right-click an Intruder payload-position request.");
    }

    private final class MenuProvider implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            if (!event.isFromTool(ToolType.INTRUDER)
                    || !event.isFrom(InvocationType.INTRUDER_PAYLOAD_POSITIONS)) {
                return Collections.emptyList();
            }
            JMenu submenu = new JMenu("Intruder Python Scripts");
            JMenuItem copy = new JMenuItem("Copy to clipboard…");
            copy.addActionListener(ignored -> SwingUtilities.invokeLater(() -> generateConfigured(event, copy, true)));
            JMenuItem save = new JMenuItem("Save to file…");
            save.addActionListener(ignored -> SwingUtilities.invokeLater(() -> generateConfigured(event, save, false)));
            submenu.add(copy);
            submenu.add(save);
            return List.of(submenu);
        }
    }

    private void generateConfigured(ContextMenuEvent event, Component parent, boolean copyToClipboard) {
        try {
            HttpRequestResponse requestResponse = event.messageEditorRequestResponse()
                    .map(value -> value.requestResponse())
                    .orElseGet(() -> event.selectedRequestResponses().isEmpty()
                            ? null : event.selectedRequestResponses().getFirst());
            if (requestResponse == null) throw new IllegalArgumentException("No Intruder request is available.");
            HttpRequest request = requestResponse.request();
            String markedRequest = PayloadPositionExtractor.requestWithMarkers(requestResponse);
            int positions = IntruderRequestParser.parse(markedRequest).positionCount();
            ScriptConfiguration configuration = BurpStyleConfigDialog.show(parent, positions);
            if (configuration == null) return;
            var service = request.httpService();
            RequestModel model = new RequestModel(markedRequest, service.secure() ? "https" : "http",
                    service.host(), service.port());
            String script = ConfiguredScriptGenerator.generate(model, configuration);
            if (copyToClipboard) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(script), null);
                JOptionPane.showMessageDialog(parent, "Python script copied to the clipboard.",
                        "Script generated", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JFileChooser chooser = new JFileChooser();
                chooser.setSelectedFile(new java.io.File("intruder_attack.py"));
                if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) return;
                Files.writeString(chooser.getSelectedFile().toPath(), script, StandardCharsets.UTF_8);
                JOptionPane.showMessageDialog(parent, "Saved " + chooser.getSelectedFile().getAbsolutePath(),
                        "Script generated", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception exception) {
            api.logging().logToError(exception);
            JOptionPane.showMessageDialog(parent, exception.getMessage(), "Could not generate script",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

}
