package com.procolorview.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.procolorview.theme.ProColorTheme;

import java.awt.Component;

/**
 * Editor de requests HTTP con syntax highlighting.
 */
public class ProColorRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private final MontoyaApi api;
    private final ProColorEditor editor;
    private HttpRequest currentRequest;

    public ProColorRequestEditor(MontoyaApi api) {
        this.api = api;
        ProColorTheme theme = ProColorTheme.fromBurp(api);
        this.editor = new ProColorEditor(api, theme);
    }

    @Override
    public HttpRequest getRequest() {
        if (editor.isModified()) {
            return HttpRequest.httpRequest(new String(editor.getContent()));
        }
        return currentRequest;
    }

    @Override
    public void setRequestResponse(burp.api.montoya.http.message.HttpRequestResponse requestResponse) {
        this.currentRequest = requestResponse.request();
        editor.setContent(currentRequest.toByteArray().getBytes(), true);
        // Store original HttpService (host/port/https) for Send to Intruder/Repeater
        if (currentRequest.httpService() != null) {
            editor.setOriginalService(currentRequest.httpService());
        }
        // Guardar response como companion para la ventana Snap
        if (requestResponse.response() != null) {
            editor.setCompanion(requestResponse.response().toByteArray().getBytes(), false);
        } else {
            editor.setCompanion(null, false);
        }
    }

    @Override
    public boolean isEnabledFor(burp.api.montoya.http.message.HttpRequestResponse requestResponse) {
        return requestResponse.request() != null;
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
