Analyzes JavaScript files to extract API endpoints, hardcoded secrets, and vulnerability sinks using static analysis and LLM-powered inspection.

---

## Quick Start

**Requirements:** Python 3.8+

```bash
# Windows
python JSpy.py

# Linux/macOS
python3 JSpy.py
```

First run will:
1. Install missing dependencies
2. Prompt for LLM API key (Anthropic/OpenAI/Gemini)
3. Launch main menu

---

## Usage

### Command-Based Interface

JSpy uses an intuitive command-based interface. Type commands directly or use numbers:

**Quick Commands:**
- `file`, `analyze`, `1` - Analyze single JS file or URL
- `dir`, `folder`, `2` - Analyze directory (recursive)
- `config`, `keys`, `3` - Configure/update API keys
- `reports`, `history`, `4` - View report history
- `view`, `show`, `5` - View specific report by ID
- `clear`, `6` - Clear report history
- `help`, `?`, `7` - Show help
- `exit`, `quit`, `8` - Exit
- `clear-keys`, `9` - Clear all API keys
- `menu` - Show command menu

**Examples:**
```
JSpy> file
Enter JS URL or file path: https://target.com/app.js

JSpy> reports
[Shows history list]

JSpy> view
Enter report ID to view: 5

JSpy> help
[Shows all commands]
```

### Examples

**Single file:**
```
JSpy> file
Enter JS URL or file path: https://target.com/app.js
JSON output? [y/N]: n
✓ Report saved: ~/.jspy/reports/20250115_143022_app.md
```

**Directory:**
```
JSpy> dir
Enter directory path: ./scraped_js/
JSON output? [y/N]: n
✓ Report saved: ~/.jspy/reports/20250115_143045_scraped_js.md
```

**View reports:**
```
JSpy> reports
[Shows history with IDs]

JSpy> view
Enter report ID to view: 3
[Displays full report]
```

**Input formats:**
- URLs: `https://example.com/app.js`
- Windows: `C:\path\to\file.js`
- Linux/Mac: `/path/to/file.js` or `./relative/path.js`

**Report Storage:**
- Reports automatically saved to `~/.jspy/reports/` with timestamps
- History tracked in `~/.jspy/history.json`
- Use `reports` command to see all previous analyses
- Use `view` command to display specific reports

---

## What JSpy Detects

- **Endpoints:** REST APIs, GraphQL, WebSockets, admin/debug paths
- **Secrets:** API keys, OAuth tokens, passwords, JWT secrets, DB connections
- **Vulnerability Sinks:** `eval()`, `innerHTML`, `postMessage()`, `document.write()`, `new Function()`, etc.
- **LLM Insights:** Business logic flaws, auth bypass patterns, insecure data handling

---

## API Keys

JSpy requires at least one LLM API key:

| Provider | Get Key | Notes |
|----------|---------|-------|
| **Anthropic** (recommended) | [console.anthropic.com](https://console.anthropic.com/) | Best code analysis |
| **OpenAI** | [platform.openai.com](https://platform.openai.com/) | Good performance |
| **Google Gemini** | [aistudio.google.com](https://aistudio.google.com/) | Large context |

Keys are stored securely in your system's credential manager (Windows Credential Manager / macOS Keychain / Linux Secret Service).

**Key Management:**
- Keys are saved automatically and don't need to be re-entered each time
- Use `config` or `keys` command to update/add keys
- Use `clear-keys` command to remove all API keys
- Setup wizard skips API key prompt if keys already exist

**Headless servers:** Use environment variables:
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python3 JSpy.py
```

---

## Report Storage

All reports are automatically saved to `~/.jspy/reports/` with timestamped filenames. Use the menu to:
- View history of all reports (Option 4)
- View specific reports by ID (Option 5)
- Clear history while keeping report files (Option 6)

## Output Formats

**Markdown (default):** Human-readable report with endpoints, secrets, sinks, and LLM analysis.

**JSON:** Use `JSON output? [y/N]: y` for automation:
```json
{
  "endpoints": ["/api/v1/users"],
  "secrets": [{"type": "API_KEY", "value": "..."}],
  "sinks": ["innerHTML at line 423"],
  "llm_insights": "..."
}
```

---

## Troubleshooting

**Package installation fails:**
```bash
pip install requests jsbeautifier esprima anthropic openai google-generativeai keyring click
```

**API key not recognized:**
- Re-enter via Option 3, or
- Set as environment variable: `export ANTHROPIC_API_KEY="sk-ant-..."`

**Keyring issues (headless Linux):**
Use environment variables instead of keyring.

---

## Tips

- Scrape JS files first (use `getJS` or browser devtools), then analyze the directory
- Prioritize main bundles (`app.js`, `main.js`, `bundle.js`)
- Use JSON output for automation: `cat report.json | jq '.endpoints[]'`

---

## Responsible Use

For **authorized security testing only**. Obtain permission, stay in scope, report responsibly.

---

## Credits

- **Author:** Traphic
- **LinkFinder:** GerbenJavado
- **SecretFinder:** m4ll0k
