package com.procolorview.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

/**
 * Provider que registra el tab "Pro Color" para HTTP responses.
 */
public class ProColorResponseEditorProvider implements HttpResponseEditorProvider {

    private final MontoyaApi api;

    public ProColorResponseEditorProvider(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext context) {
        return new ProColorResponseEditor(api);
    }
}
