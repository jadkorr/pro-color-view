package com.procolorview;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.procolorview.editor.ProColorRequestEditorProvider;
import com.procolorview.editor.ProColorResponseEditorProvider;
import com.procolorview.ai.AiConfig;
import com.procolorview.util.ColorConfig;
import com.procolorview.util.TemplateVars;

/**
 * Pro Color View v2.0 — Extensión de Burp Suite (Montoya API)
 *
 * Editor de mensajes HTTP con syntax highlighting para:
 *   - Líneas de request/response
 *   - Headers (destacando headers sensibles)
 *   - Body: JSON, XML, HTML, Form-urlencoded
 *
 * Mejoras sobre v1 (Jython):
 *   - Java nativo → mejor rendimiento y compatibilidad
 *   - API Montoya (reemplaza IBurpExtender legacy)
 *   - Colorización de XML/HTML en el body
 *   - Colorización de form-urlencoded con URL-decode
 *   - Búsqueda con regex y contador de coincidencias
 *   - Arquitectura modular (editor, parser, colorizer, search, theme)
 */
public class ProColorExtension implements BurpExtension {

    private static final String NAME = "Pro Color View";
    private static final String VERSION = "5.0.0";

    @Override
    public void initialize(MontoyaApi api) {
        Logging logging = api.logging();

        api.extension().setName(NAME);

        // Initialize template variables, color config, and AI config with persistence
        TemplateVars.init(api);
        ColorConfig.init(api);
        AiConfig.init(api);

        // Registrar providers para Request y Response
        api.userInterface().registerHttpRequestEditorProvider(
                new ProColorRequestEditorProvider(api));
        api.userInterface().registerHttpResponseEditorProvider(
                new ProColorResponseEditorProvider(api));

        logging.logToOutput("[%s] v%s cargado correctamente.".formatted(NAME, VERSION));
    }
}
