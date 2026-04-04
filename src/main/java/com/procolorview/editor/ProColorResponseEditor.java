package com.procolorview.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import com.procolorview.theme.ProColorTheme;

import java.awt.Component;

/**
 * Editor de responses HTTP con syntax highlighting.
 */
public class ProColorResponseEditor implements ExtensionProvidedHttpResponseEditor {

    private final MontoyaApi api;
    private final ProColorEditor editor;
    private HttpResponse currentResponse;

    public ProColorResponseEditor(MontoyaApi api) {
        this.api = api;
        ProColorTheme theme = ProColorTheme.fromBurp(api);
        this.editor = new ProColorEditor(api, theme);
    }

    @Override
    public HttpResponse getResponse() {
        if (editor.isModified()) {
            return HttpResponse.httpResponse(new String(editor.getContent()));
        }
        return currentResponse;
    }

    @Override
    public void setRequestResponse(burp.api.montoya.http.message.HttpRequestResponse requestResponse) {
        this.currentResponse = requestResponse.response();
        if (currentResponse != null) {
            editor.setContent(currentResponse.toByteArray().getBytes(), false);
        } else {
            editor.setContent(null, false);
        }
        // Guardar request como companion para la ventana Snap
        if (requestResponse.request() != null) {
            editor.setCompanion(requestResponse.request().toByteArray().getBytes(), true);
        } else {
            editor.setCompanion(null, true);
        }
    }

    @Override
    public boolean isEnabledFor(burp.api.montoya.http.message.HttpRequestResponse requestResponse) {
        return requestResponse.response() != null;
    }

    @Override
    public String caption() {
        return "Pro Color";
    }

    @Override
    public Component uiComponent() {
        return editor.getComponent();
    }

    @Override
    public Selection selectedData() {
        byte[] sel = editor.getSelectedData();
        if (sel == null) return null;
        return Selection.selection(0, sel.length);
    }

    @Override
    public boolean isModified() {
        return editor.isModified();
    }
}
