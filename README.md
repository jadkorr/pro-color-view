# Pro Color View - Burp Suite Extension

Advanced HTTP message editor for Burp Suite with syntax highlighting, AI-powered vulnerability testing, security tools, and productivity features built on the Montoya API.

![Java](https://img.shields.io/badge/Java-17+-blue) ![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Montoya%20API-orange) ![Version](https://img.shields.io/badge/version-5.0.0-green)

## Features

### AI Vulnerability Testing
- Integrated AI panel supporting **OpenAI**, **Anthropic (Claude)**, **Google Gemini**, and **OpenRouter**
- Two-phase execution: AI analyzes request and generates test payloads → Burp executes them → AI provides final verdict
- Configurable provider and API key via UI
- Custom prompt support for targeted testing (XSS, SQLi, SSRF, SSTI, etc.)

### Syntax Highlighting
- Full colorization for HTTP request/response lines, headers, and bodies
- Supports JSON, XML, HTML, JavaScript, Form URL-encoded, and Multipart bodies
- Sensitive headers highlighted (Authorization, Cookie, API keys)
- **Configurable parameter colors** for URL params and form body values
- Dark and light themes that adapt to Burp's look and feel

### Editor Tools
- **Search & Replace** with regex support and match counter
- **Highlight & Blur** overlays for focusing on specific patterns
- **Pretty/Minify** toggle for JSON bodies
- **Word Wrap** and **Line Numbers** toggle
- **Undo/Redo** with optimized history
- **Editor History** with snapshots, restore, and rename
- **Annotation Panel** for editor notes

### Security & Pentest Tools
- **Template Variables** with project persistence — define `{{token}}`, `{{xss_payload}}`, etc. Auto-replaced on Send to Repeater/Intruder
- **Payload Presets** — XSS, Blind XSS (Collaborator), RCE (Collaborator), SQLi, SSRF, SSTI with ready-to-use values
- **Insert Collaborator Payload** — inject Burp Collaborator domains at cursor position
- **Minimize Headers** — toggle visibility of noise headers on requests and responses (non-destructive, headers can be restored)
- **Change Request Format** — convert between JSON, URL Encoded, XML, Multipart, and GET with automatic parameter migration
- **Find Secrets** — detect API keys, tokens, and credentials in responses
- **Find Links** — extract URLs and endpoints
- **Find Comments** — locate HTML/JS comments
- **Find Scripts** — identify inline and external JavaScript
- **Find Forms** — extract form actions, methods, and inputs
- **JWT Decode** — decode and inspect JSON Web Tokens
- **CSRF PoC Generator** — auto-generate proof of concept HTML forms
- **Copy as cURL** — export request as cURL command

### Bidirectional Decoder Panel
- Select encoded text → decoded value appears below (editable)
- Edit decoded text → automatically re-encoded in the editor
- Supports Base64, URL, Hex, HTML, Unicode encoding
- JWT display (read-only, signature required)
- Replace and Copy buttons for quick workflow

### Snap Window
- Side-by-side request/response viewer in a popup window
- Independent Highlight & Blur overlays
- Configurable size and orientation (horizontal/vertical)
- Hotkey: `Ctrl+Shift+S` (or `Cmd+Shift+S` on Mac)
- One-time config with saved defaults

### Burp Integration
- Send to Repeater / Intruder / Organizer / Comparer
- Open response in browser
- Create scan issue
- Copy URL

### Performance
- Zero memory leaks — proper cleanup of all listeners, workers, and caches
- Async rendering for large responses (>30KB) with instant plain-text fallback
- LRU document cache to skip re-colorization of recently viewed messages
- Optimized undo history and resource disposal

## Installation

### Option 1: Pre-built JAR
1. Download the latest `pro-color-view-5.0.0.jar` from the [Releases](../../releases) page
2. In Burp Suite, go to **Extensions** > **Installed** > **Add**
3. Select **Extension type: Java**
4. Select the downloaded JAR file
5. Click **Next** — the extension loads automatically

### Option 2: Build from Source
Requirements: JDK 17+, Montoya API JAR

```bash
# Clone the repository
git clone https://github.com/arthusu/pro-color-view.git
cd pro-color-view

# Download the Montoya API (if not already available)
# https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/

# Compile
mkdir -p build/classes/META-INF/services
echo "com.procolorview.ProColorExtension" > build/classes/META-INF/services/burp.api.montoya.BurpExtension
javac -cp montoya-api.jar -d build/classes --source-path src/main/java \
  $(find src -name "*.java")

# Package
cd build/classes
jar cf ../../pro-color-view-5.0.0.jar META-INF/ com/
```

## Project Structure

```
pro-color-view/
├── src/main/java/com/procolorview/
│   ├── ProColorExtension.java          # Extension entry point
│   ├── ai/
│   │   ├── AiPanel.java               # AI vulnerability testing UI panel
│   │   ├── AiExecutor.java            # AI API client (OpenAI, Anthropic, Gemini, OpenRouter)
│   │   └── AiConfig.java              # AI provider configuration and persistence
│   ├── colorizer/
│   │   ├── HttpColorizer.java          # Main syntax highlighting orchestrator
│   │   ├── JsonColorizer.java          # JSON body colorizer
│   │   ├── XmlColorizer.java           # XML/HTML body colorizer
│   │   ├── JsColorizer.java            # JavaScript colorizer
│   │   └── FormColorizer.java          # URL-encoded form colorizer
│   ├── editor/
│   │   ├── ProColorEditor.java         # Main editor UI with cleanup lifecycle
│   │   ├── ProColorRequestEditor.java  # Montoya request editor adapter
│   │   ├── ProColorResponseEditor.java # Montoya response editor adapter
│   │   ├── ProColorRequestEditorProvider.java
│   │   ├── ProColorResponseEditorProvider.java
│   │   ├── AnnotationPanel.java        # Editor annotation notes
│   │   ├── WrapTextPane.java           # Custom JTextPane with word wrap
│   │   ├── WrapEditorKit.java          # EditorKit for wrap support
│   │   ├── WrapLayout.java             # FlowLayout that wraps to next line
│   │   └── LineNumberGutter.java       # Line number panel
│   ├── overlay/
│   │   └── OverlayManager.java         # Highlight & Blur overlay engine
│   ├── parser/
│   │   ├── HttpMessageParser.java      # HTTP message parser
│   │   └── ParsedHttpMessage.java      # Parsed message data structure
│   ├── search/
│   │   └── SearchManager.java          # Search & replace engine
│   ├── theme/
│   │   └── ProColorTheme.java          # Theme configuration
│   └── util/
│       ├── TemplateVars.java           # Template variables with persistence
│       ├── ColorConfig.java            # Configurable parameter colors
│       ├── EditorHistory.java          # Snapshot history manager
│       ├── CurlExporter.java           # cURL command exporter
│       ├── JwtDecoder.java             # JWT decoder
│       ├── SecretsFinder.java          # Secret/credential detector
│       ├── LinkFinder.java             # URL/endpoint extractor
│       ├── Base64Detector.java         # Base64 detection
│       └── Decoder.java               # Multi-format decoder panel
├── pro-color-view-5.0.0.jar           # Pre-built extension
└── README.md
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+F` | Search |
| `Ctrl+H` | Replace |
| `Ctrl+Z` | Undo |
| `Ctrl+Shift+Z` | Redo |
| `Ctrl+P` | Toggle Pretty/Minify |
| `Ctrl+T` | Template Variables Manager |
| `Ctrl+Shift+S` | Snap Window |
| `Ctrl+G` | Go to Line |

*On Mac, use `Cmd` instead of `Ctrl`*

## Template Variables

Define variables once, use everywhere with `{{variable_name}}` syntax. Variables are automatically replaced when sending to Repeater or Intruder.

Built-in presets include ready-to-use payloads for: XSS, Blind XSS with Burp Collaborator, RCE with Collaborator, SQLi, SSRF, and SSTI.

Variables persist in the Burp project file — they survive extension reloads and project re-opens.

## AI Testing Setup

1. Click the **AI** button in the editor toolbar
2. Select your provider (OpenAI, Anthropic, Gemini, or OpenRouter)
3. Enter your API key when prompted
4. Select a test type or write a custom prompt
5. Click **Execute** — the AI generates payloads, Burp sends them, and the AI analyzes results

API keys are stored in the Burp project file and persist across sessions.

## Requirements

- Burp Suite Professional or Community (2023.1+)
- Java 17 or higher

## License

MIT License

## Author

Jesus Espinoza (@arthusuxD)
