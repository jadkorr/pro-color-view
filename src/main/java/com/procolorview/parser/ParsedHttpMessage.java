package com.procolorview.parser;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Representación parseada de un mensaje HTTP (request o response).
 */
public record ParsedHttpMessage(
        String rawHead,
        String rawBody,
        String startLine,
        List<Map.Entry<String, String>> headers,
        BodyType bodyType,
        String prettyBody,
        boolean isRequest
) {

    public enum BodyType {
        JSON, XML, HTML, JAVASCRIPT, FORM, NONE
    }

    public boolean hasBody() {
        return rawBody != null && !rawBody.isBlank();
    }

    /**
     * Devuelve el body a renderizar: prettyBody si existe, si no rawBody.
     */
    public String displayBody() {
        if (prettyBody != null && !prettyBody.isBlank()) return prettyBody;
        return rawBody != null ? rawBody : "";
    }

    /**
     * Reconstruye el mensaje HTTP completo (head + body).
     */
    public String rebuild() {
        if (hasBody()) {
            return rawHead + "\r\n\r\n" + rawBody;
        }
        return rawHead;
    }
}
