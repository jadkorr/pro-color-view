# Pro Color View - Burp Suite Extension

Advanced HTTP message editor for Burp Suite with syntax highlighting, security tools, and productivity features built on the Montoya API.

![Java](https://img.shields.io/badge/Java-17+-blue) ![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Montoya%20API-orange) ![Version](https://img.shields.io/badge/version-4.4.0-green)

## Features

### Syntax Highlighting
- Full colorization for HTTP request/response lines, headers, and bodies
- Supports JSON, XML, HTML, JavaScript, Form URL-encoded, and Multipart bodies
- Sensitive headers highlighted (Authorization, Cookie, API keys)
- Dark theme that adapts to Burp's look and feel

### Editor Tools
- **Search & Replace** with regex support and match counter
- **Highlight & Blur** overlays for focusing on specific patterns
- **Pretty/Minify** toggle for JSON bodies
- **Word Wrap** and **Line Numbers** toggle
- **Undo/Redo** with 200-level history
- **Editor History** with snapshots, restore, and rename

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

## Installation

### Option 1: Pre-built JAR
1. Download the latest `pro-color-view-4.4.0.jar` from the [Releases](../../releases) page
2. In Burp Suite, go to **Extensions** > **Installed** > **Add**
3. Select **Extension type: Java**
4. Select the downloaded JAR file
5. Click **Next** — the extension loads automatically

### Option 2: Build from Source
Requirements: JDK 17+, Montoya API JAR

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/pro-color-view.git
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
jar cf ../../pro-color-view-4.4.0.jar META-INF/ com/
```

## Project Structure

```
pro-color-view/
├── src/main/java/com/procolorview/
│   ├── ProColorExtension.java          # Extension entry point
│   ├── colorizer/
│   │   ├── HttpColorizer.java          # Main syntax highlighting orchestrator
│   │   ├── JsonColorizer.java          # JSON body colorizer
│   │   ├── XmlColorizer.java           # XML/HTML body colorizer
│   │   ├── JsColorizer.java            # JavaScript colorizer
│   │   └── FormColorizer.java          # URL-encoded form colorizer
│   ├── editor/
│   │   ├── ProColorEditor.java         # Main editor UI (~3100 lines)
│   │   ├── ProColorRequestEditor.java  # Montoya request editor adapter
│   │   ├── ProColorResponseEditor.java # Montoya response editor adapter
│   │   ├── ProColorRequestEditorProvider.java
│   │   ├── ProColorResponseEditorProvider.java
│   │   ├── WrapTextPane.java           # Custom JTextPane with word wrap
│   │   ├── WrapEditorKit.java          # EditorKit for wrap support
│   │   ├── WrapLayout.java             # FlowLayout that wraps to next line
│   │   └── LineNumberGutter.java       # Line number panel
│   ├── overlay/
│   │   └── OverlayManager.java         # Highlight & Blur overlay engine
│   ├── parser/
│   │   ├── HttpMessageParser.java      # HTTP message parser
│   │   └── ParsedHttpMessage.java      # Parsed message record
│   ├── search/
│   │   └── SearchManager.java          # Search & replace engine
│   ├── theme/
│   │   └── ProColorTheme.java          # Theme configuration
│   └── util/
│       ├── TemplateVars.java           # Template variables with persistence
│       ├── EditorHistory.java          # Snapshot history manager
│       ├── CurlExporter.java           # cURL command exporter
│       ├── JwtDecoder.java             # JWT decoder
│       ├── SecretsFinder.java          # Secret/credential detector
│       ├── LinkFinder.java             # URL/endpoint extractor
│       ├── Base64Detector.java         # Base64 detection
│       └── Decoder.java               # Multi-format decoder panel
├── pro-color-view-4.4.0.jar           # Pre-built extension
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

## Requirements

- Burp Suite Professional or Community (2023.1+)
- Java 17 or higher

## License

MIT License

## Author

Jesus Espinoza (@jespinozasoto3)
