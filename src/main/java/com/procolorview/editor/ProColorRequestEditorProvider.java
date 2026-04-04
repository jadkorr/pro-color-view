package com.procolorview.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

/**
 * Provider que registra el tab "Pro Color" para HTTP requests.
 */
public class ProColorRequestEditorProvider implements HttpRequestEditorProvider {

    private final MontoyaApi api;

    public ProColorRequestEditorProvider(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext context) {
        return new ProColorRequestEditor(api);
    }
}
