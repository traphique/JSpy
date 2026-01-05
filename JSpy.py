# jspy.py - JavaScript Intelligence Extractor
# Just run: python JSpy.py (seamless setup included)

from __future__ import annotations

import sys
import subprocess
import os
import json
import glob
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass, field

SERVICE_NAME = "jspy"
BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║     ██╗███████╗██████╗ ██╗   ██╗                              ║
║     ██║██╔════╝██╔══██╗╚██╗ ██╔╝                              ║
║     ██║███████╗██████╔╝ ╚████╔╝                               ║
║██   ██║╚════██║██╔═══╝   ╚██╔╝                                ║
║╚█████╔╝███████║██║        ██║                                 ║
║ ╚════╝ ╚══════╝╚═╝        ╚═╝                                 ║
║                                                               ║
║  JSpy v0.2 - JavaScript Intelligence Extractor                ║
║  Produced by Traphic                                          ║
║  Extracts endpoints, secrets, vulns from JS with LLM insights ║
╚═══════════════════════════════════════════════════════════════╝
"""

# Required pip packages (no external git tools needed!)
PIP_PACKAGES = [
    "requests",
    "jsbeautifier", 
    "esprima",
    "anthropic",
    "openai",
    "google-generativeai",
    "keyring",
    "click"
]

# ══════════════════════════════════════════════════════════════════════════════
# BUILT-IN LINK FINDER (based on LinkFinder by GerbenJavado)
# ══════════════════════════════════════════════════════════════════════════════

# Regex pattern to find endpoints/URLs in JavaScript
LINK_REGEX = re.compile(r"""
    (?:"|')                                 # Start with quote
    (
        (?:[a-zA-Z]{1,10}://|//)            # Protocol or //
        [^"'/]{1,}                          # Domain/path
        \.[a-zA-Z]{2,}[^"']{0,}             # TLD and rest
        |
        (?:/|\.\./|\./)                     # Relative path start
        [^"'><,;| *()(%%$^/\\\[\]]          # Valid path chars
        [^"'><,;|()]{1,}                    # Rest of path
        |
        [a-zA-Z0-9_\-/]{1,}/                # Path with slash
        [a-zA-Z0-9_\-/]{1,}                 # More path
        \.(?:[a-zA-Z]{1,4}|action)          # Extension
        (?:[\?|#][^"|']{0,}|)               # Query/fragment
        |
        [a-zA-Z0-9_\-/]{1,}/                # API-style path
        [a-zA-Z0-9_\-/]{3,}                 # Endpoint
        (?:[\?|#][^"|']{0,}|)               # Query/fragment
        |
        [a-zA-Z0-9_\-]{1,}                  # Simple name
        \.(?:php|asp|aspx|jsp|json|
             action|html|js|txt|xml|api)    # Common extensions
        (?:[\?|#][^"|']{0,}|)               # Query/fragment
    )
    (?:"|')                                 # End with quote
""", re.VERBOSE | re.IGNORECASE)

# Additional patterns for API endpoints
API_PATTERNS = [
    re.compile(r'["\'](/api/[^"\']+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/v[0-9]+/[^"\']+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/graphql[^"\']*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/rest/[^"\']+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/ajax/[^"\']+)["\']', re.IGNORECASE),
    re.compile(r'["\']([^"\']*\.json)["\']', re.IGNORECASE),
    re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']', re.IGNORECASE),
]

# ══════════════════════════════════════════════════════════════════════════════
# BUILT-IN SECRET FINDER (based on SecretFinder by m4ll0k)
# ══════════════════════════════════════════════════════════════════════════════

SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "AWS Secret Key": re.compile(r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]'),
    "Google API Key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "Google OAuth": re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
    "GitHub Token": re.compile(r'(?i)(gh[pousr]_[A-Za-z0-9_]{36,}|github[_\-]?token.{0,20}[\'"][0-9a-zA-Z]{35,40}[\'"])'),
    "Slack Token": re.compile(r'xox[baprs]-([0-9a-zA-Z]{10,48})'),
    "Slack Webhook": re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}'),
    "Stripe API Key": re.compile(r'(?i)stripe.{0,20}[\'"]sk_live_[0-9a-zA-Z]{24}[\'"]'),
    "Stripe Publishable": re.compile(r'pk_live_[0-9a-zA-Z]{24}'),
    "Square Access Token": re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}'),
    "Square OAuth Secret": re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}'),
    "PayPal Token": re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'),
    "Twilio API Key": re.compile(r'SK[0-9a-fA-F]{32}'),
    "Twilio Account SID": re.compile(r'AC[a-zA-Z0-9_\-]{32}'),
    "SendGrid API Key": re.compile(r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}'),
    "Mailgun API Key": re.compile(r'key-[0-9a-zA-Z]{32}'),
    "Mailchimp API Key": re.compile(r'[0-9a-f]{32}-us[0-9]{1,2}'),
    "Firebase URL": re.compile(r'https://[a-z0-9-]+\.firebaseio\.com'),
    "Firebase API Key": re.compile(r'(?i)firebase.{0,20}[\'"][a-zA-Z0-9_-]{39}[\'"]'),
    "Heroku API Key": re.compile(r'(?i)heroku.{0,20}[\'"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\'"]'),
    "JWT Token": re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
    "Bearer Token": re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.=]+'),
    "Basic Auth": re.compile(r'(?i)basic\s+[a-zA-Z0-9=:_\+\/-]{5,100}'),
    "Private Key": re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
    "SSH Private Key": re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
    "PGP Private Key": re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    "Generic API Key": re.compile(r'(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token).{0,20}[\'"][0-9a-zA-Z]{16,64}[\'"]'),
    "Generic Secret": re.compile(r'(?i)(?:secret|password|passwd|pwd|token|auth|credential|cred).{0,20}[\'"][^\'"]{8,64}[\'"]'),
    "Database URL": re.compile(r'(?i)(?:mongodb|postgres|mysql|redis|amqp|elasticsearch)://[^\s"\'<>]+'),
    "S3 Bucket": re.compile(r'(?i)(?:s3\.amazonaws\.com/[a-zA-Z0-9_-]+|[a-zA-Z0-9_-]+\.s3\.amazonaws\.com)'),
    "Azure Storage": re.compile(r'https://[a-zA-Z0-9]+\.blob\.core\.windows\.net'),
    "Discord Webhook": re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+'),
    "Discord Bot Token": re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}'),
    "Telegram Bot Token": re.compile(r'[0-9]+:AA[0-9A-Za-z_-]{33}'),
    "OpenAI API Key": re.compile(r'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}'),
    "Anthropic API Key": re.compile(r'sk-ant-[a-zA-Z0-9_-]{40,}'),
}

# ══════════════════════════════════════════════════════════════════════════════
# DANGEROUS SINK PATTERNS
# ══════════════════════════════════════════════════════════════════════════════

SINK_PATTERNS = [
    (re.compile(r'\beval\s*\('), 'eval()'),
    (re.compile(r'\.innerHTML\s*='), 'innerHTML assignment'),
    (re.compile(r'\.outerHTML\s*='), 'outerHTML assignment'),
    (re.compile(r'document\.write\s*\('), 'document.write()'),
    (re.compile(r'\.postMessage\s*\('), 'postMessage()'),
    (re.compile(r'\.setAttribute\s*\(\s*["\']on\w+'), 'Event handler attribute'),
    (re.compile(r'new\s+Function\s*\('), 'new Function()'),
    (re.compile(r'setTimeout\s*\(\s*["\']'), 'setTimeout with string'),
    (re.compile(r'setInterval\s*\(\s*["\']'), 'setInterval with string'),
    (re.compile(r'location\s*='), 'location assignment'),
    (re.compile(r'location\.href\s*='), 'location.href assignment'),
    (re.compile(r'\.src\s*=\s*[^"\']+\+'), 'Dynamic src assignment'),
]


# ══════════════════════════════════════════════════════════════════════════════
# BUILT-IN FINDERS (No external dependencies!)
# ══════════════════════════════════════════════════════════════════════════════

def find_links(code: str) -> List[str]:
    """Find all endpoints/URLs in JavaScript code (built-in LinkFinder)."""
    endpoints = set()
    
    # Main regex pattern
    matches = LINK_REGEX.findall(code)
    for match in matches:
        endpoint = match.strip()
        # Filter out common false positives
        if (endpoint and 
            len(endpoint) > 2 and
            not endpoint.startswith('//') or '/' in endpoint[2:]):
            # Clean up the endpoint
            if endpoint.startswith(('/', './', '../', 'http')):
                endpoints.add(endpoint)
            elif '/' in endpoint:
                endpoints.add('/' + endpoint if not endpoint.startswith('/') else endpoint)
    
    # Additional API-specific patterns
    for pattern in API_PATTERNS:
        for match in pattern.findall(code):
            if match and len(match) > 2:
                endpoints.add(match)
    
    # Filter and clean results
    filtered = set()
    excluded_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.woff', '.woff2', '.ttf', '.eot'}
    excluded_patterns = {'node_modules', 'webpack', '__webpack', '.map', 'sourcemap'}
    
    for ep in endpoints:
        # Skip static assets and common noise
        if any(ep.lower().endswith(ext) for ext in excluded_extensions):
            continue
        if any(pattern in ep.lower() for pattern in excluded_patterns):
            continue
        if len(ep) > 500:  # Skip very long strings (probably not endpoints)
            continue
        filtered.add(ep)
    
    return sorted(filtered)


def find_secrets(code: str) -> List[Dict[str, str]]:
    """Find secrets/API keys in JavaScript code (built-in SecretFinder)."""
    secrets = []
    seen = set()  # Avoid duplicates
    
    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(code):
            value = match.group(0)
            
            # Skip if already found
            if value in seen:
                continue
            seen.add(value)
            
            # Get context (surrounding text)
            start = max(0, match.start() - 30)
            end = min(len(code), match.end() + 30)
            context = code[start:end].replace('\n', ' ').strip()
            
            # Check if it's likely a real secret vs a placeholder
            is_placeholder = any(x in value.lower() for x in [
                'example', 'placeholder', 'your_', 'xxx', 'test', 'demo', 
                'sample', 'fake', 'dummy', '1234567890', 'abcdef'
            ])
            
            secrets.append({
                "type": secret_type,
                "value": value[:100] + "..." if len(value) > 100 else value,
                "context": context[:100] + "..." if len(context) > 100 else context,
                "confidence": "low" if is_placeholder else "high"
            })
    
    return secrets


# ══════════════════════════════════════════════════════════════════════════════
# SETUP & INSTALLATION
# ══════════════════════════════════════════════════════════════════════════════

import threading
import time
import itertools


class Spinner:
    """Animated spinner for long-running operations."""
    
    def __init__(self, message: str = ""):
        self.message = message
        self.running = False
        self.thread = None
        self.frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    
    def _spin(self):
        for frame in itertools.cycle(self.frames):
            if not self.running:
                break
            print(f"\r  {frame} {self.message}", end="", flush=True)
            time.sleep(0.1)
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.start()
    
    def stop(self, success: bool = True, final_message: str = ""):
        self.running = False
        if self.thread:
            self.thread.join()
        # Clear the line and print final status
        status = "✓" if success else "✗"
        msg = final_message if final_message else self.message
        print(f"\r  {status} {msg}          ")
    
    def update(self, message: str):
        self.message = message


def print_progress_bar(current: int, total: int, prefix: str = "", width: int = 30) -> None:
    """Print a progress bar."""
    percent = current / total
    filled = int(width * percent)
    bar = "█" * filled + "░" * (width - filled)
    print(f"\r  {prefix} [{bar}] {current}/{total} ({percent*100:.0f}%)", end="", flush=True)


def print_step(step: int, total: int, message: str) -> None:
    """Print a formatted setup step."""
    print(f"\n{'═' * 60}")
    print(f"  Step {step}/{total}: {message}")
    print(f"{'═' * 60}")


def check_package_installed(package: str) -> bool:
    """Check if a Python package is installed."""
    try:
        __import__(package.replace("-", "_").replace("google-generativeai", "google.generativeai"))
        return True
    except ImportError:
        return False


def install_single_package(package: str) -> Tuple[bool, str]:
    """Install a single pip package. Returns (success, error_message)."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", package],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return True, ""
        else:
            return False, result.stderr.strip()[:100]
    except Exception as e:
        return False, str(e)[:100]


def install_pip_packages() -> bool:
    """Install required pip packages with progress indicator."""
    # Check which are installed vs missing
    installed = []
    missing = []
    
    for pkg in PIP_PACKAGES:
        if check_package_installed(pkg):
            installed.append(pkg)
        else:
            missing.append(pkg)
    
    # Show already installed packages
    if installed:
        print(f"\n  ✓ Already installed: {', '.join(installed)}")
    
    if not missing:
        print("\n  ✅ All pip packages already installed!")
        return True
    
    print(f"\n  📦 Installing {len(missing)} missing package(s):\n")
    
    failed = []
    errors = {}
    for i, package in enumerate(missing, 1):
        # Show progress bar
        print_progress_bar(i - 1, len(missing), f"Installing {package:<20}")
        
        # Install the package
        spinner = Spinner(f"Installing {package}...")
        spinner.start()
        
        success, error_msg = install_single_package(package)
        
        if success:
            spinner.stop(True, f"{package} ✓")
        else:
            spinner.stop(False, f"{package} FAILED")
            failed.append(package)
            if error_msg:
                errors[package] = error_msg
    
    # Final progress
    print_progress_bar(len(missing), len(missing), "Complete!".ljust(20))
    print()  # New line after progress bar
    
    if failed:
        print(f"\n  ⚠ Failed to install: {', '.join(failed)}")
        for pkg, err in errors.items():
            if err:
                print(f"    • {pkg}: {err}")
        print(f"\n  Try manually: pip install {' '.join(failed)}")
        return False
    
    print(f"\n  ✅ All {len(missing)} packages installed successfully!")
    return True


def setup_dependencies() -> bool:
    """Interactive dependency installation."""
    print_step(1, 3, "Dependency Installation")
    
    # Check which pip packages are installed
    installed_pip = [pkg for pkg in PIP_PACKAGES if check_package_installed(pkg)]
    missing_pip = [pkg for pkg in PIP_PACKAGES if not check_package_installed(pkg)]
    
    # Show current status
    print("\n  Checking dependencies...\n")
    
    if installed_pip:
        print(f"  ✓ Already installed: {', '.join(installed_pip)}")
    
    # Check if everything is already installed
    if not missing_pip:
        print("\n  ════════════════════════════════════════════════════════")
        print("  ✅ All dependencies already installed! Nothing to do.")
        print("  ════════════════════════════════════════════════════════")
        return True
    
    # Show what needs to be installed
    print(f"\n  📦 Missing packages: {', '.join(missing_pip)}")
    
    # Ask user
    print()
    response = input("  Would you like to install these now? [Y/n]: ").strip().lower()
    
    if response in ('n', 'no'):
        print("\n  ⚠ Dependencies not installed. Some features may not work.")
        print("  Run JSpy again when ready to install.")
        return False
    
    print()
    
    # Install pip packages
    if not install_pip_packages():
        return False
    
    print("\n  ════════════════════════════════════════════════════════")
    print("  ✅ All dependencies installed successfully!")
    print("  ════════════════════════════════════════════════════════")
    return True


def has_api_keys() -> bool:
    """Check if any API keys are configured."""
    try:
        import keyring
        for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"]:
            if keyring.get_password(SERVICE_NAME, key):
                return True
        return False
    except:
        return False


def setup_api_credentials(force: bool = False) -> bool:
    """Interactive API key setup."""
    import keyring
    import click
    
    providers = {
        "ANTHROPIC_API_KEY": ("Anthropic", "Claude - recommended for code analysis"),
        "OPENAI_API_KEY": ("OpenAI", "GPT-4o"),
        "GEMINI_API_KEY": ("Google", "Gemini 1.5 Pro")
    }
    
    # Check existing keys
    existing = []
    for key, (name, _) in providers.items():
        if keyring.get_password(SERVICE_NAME, key):
            existing.append(name)
    
    if existing and not force:
        print(f"\n  ✓ Existing API keys found: {', '.join(existing)}")
        print("  Keys are already configured. Use 'clear-keys' to remove them.")
        response = input("  Would you like to update/add API keys? [y/N]: ").strip().lower()
        if response not in ('y', 'yes'):
            return True
    
    if not existing or force:
        if not force:
            print("\n  No API keys configured yet.")
            print("  JSpy needs at least one LLM API key for deep code analysis.")
        print("\n  Keys are stored securely in your system's credential manager.")
        print("  (Windows Credential Manager / macOS Keychain / Linux Secret Service)")
    
    print("\n  Enter your API keys below (press Enter to skip):\n")
    
    keys_set = 0
    for key, (name, desc) in providers.items():
        current = keyring.get_password(SERVICE_NAME, key)
        status = " [configured]" if current else ""
        
        value = click.prompt(
            f"  {name} API key ({desc}){status}",
            default="",
            show_default=False
        )
        
        if value:
            keyring.set_password(SERVICE_NAME, key, value)
            os.environ[key] = value
            keys_set += 1
            print(f"    ✓ {name} key saved securely")
        elif current:
            keys_set += 1
    
    if keys_set == 0:
        print("\n  ⚠ No API keys configured. LLM analysis will not be available.")
        print("  You can add keys later using 'config' or 'keys' command.")
        return False
    
    print(f"\n  ✅ {keys_set} API key(s) configured!")
    return True


def clear_api_keys() -> None:
    """Clear all API keys."""
    import click
    import keyring
    
    if not has_api_keys():
        print("\n  No API keys configured to clear.")
        return
    
    providers = {
        "ANTHROPIC_API_KEY": "Anthropic",
        "OPENAI_API_KEY": "OpenAI",
        "GEMINI_API_KEY": "Google"
    }
    
    if click.confirm("\n  ⚠ Delete all API keys? This cannot be undone.", default=False):
        cleared = []
        for key, name in providers.items():
            if keyring.get_password(SERVICE_NAME, key):
                keyring.delete_password(SERVICE_NAME, key)
                if key in os.environ:
                    del os.environ[key]
                cleared.append(name)
        
        if cleared:
            print(f"\n  ✓ Cleared {len(cleared)} API key(s): {', '.join(cleared)}")
            print("  Use 'config' or 'keys' command to add new keys.")
        else:
            print("\n  No keys were cleared.")
    else:
        print("\n  Cancelled.")


def run_setup_wizard() -> bool:
    """Run the complete setup wizard."""
    print(BANNER)
    print("\n  Welcome to JSpy! Let's get you set up.\n")
    
    # Step 1: Dependencies
    if not setup_dependencies():
        return False
    
    # Reload modules after installation
    try:
        global keyring, click, requests, jsbeautifier, esprima
        import keyring
        import click
        import requests
        import jsbeautifier
        import esprima
    except ImportError as e:
        print(f"\n  ✗ Failed to load dependencies: {e}")
        print("  Please restart JSpy.")
        return False
    
    # Step 2: API Keys (skip if already configured)
    if has_api_keys():
        print_step(2, 3, "API Key Configuration")
        print("\n  ✓ API keys already configured. Skipping setup.")
        print("  Use 'config' or 'keys' command to update, or 'clear-keys' to remove.\n")
    else:
        setup_api_credentials()
    
    # Step 3: Ready
    print_step(3, 3, "Setup Complete!")
    print("\n  🎉 JSpy is ready to use!")
    print("  You can now analyze JavaScript files for security insights.\n")
    
    input("  Press Enter to continue to the main menu...")
    return True


def check_first_run() -> bool:
    """Check if this is a first run (dependencies missing)."""
    # Check pip packages
    for pkg in PIP_PACKAGES:
        if not check_package_installed(pkg):
            return True
    
    # API keys are optional - don't require them for first run check
    # User can add them later via menu
    return False


# ══════════════════════════════════════════════════════════════════════════════
# CORE FUNCTIONALITY (loaded after dependencies are installed)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class LLMClient:
    """Cached LLM client wrapper."""
    client: Any
    model: Optional[str]
    provider: str


@dataclass
class AnalysisResult:
    """Results from analyzing a JS file."""
    input_path: str
    endpoints: List[str] = field(default_factory=list)
    secrets: List[Dict] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)
    llm_insights: str = ""
    error: Optional[str] = None


# Global caches
_llm_client_cache: Optional[LLMClient] = None
_http_session = None

# Report storage paths
JSPY_DIR = Path.home() / ".jspy"
REPORTS_DIR = JSPY_DIR / "reports"
HISTORY_FILE = JSPY_DIR / "history.json"


def get_http_session():
    """Get or create a reusable HTTP session with connection pooling."""
    global _http_session
    import requests
    
    if _http_session is None:
        _http_session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=3
        )
        _http_session.mount('http://', adapter)
        _http_session.mount('https://', adapter)
    return _http_session


def load_api_keys() -> None:
    """Load all API keys from keyring into environment."""
    import keyring
    for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"]:
        stored = keyring.get_password(SERVICE_NAME, key)
        if stored:
            os.environ[key] = stored


def get_llm_client() -> LLMClient:
    """Get or create cached LLM client (singleton pattern)."""
    global _llm_client_cache
    
    if _llm_client_cache is not None:
        return _llm_client_cache
    
    load_api_keys()
    
    if os.getenv("ANTHROPIC_API_KEY"):
        import anthropic
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        _llm_client_cache = LLMClient(client, "claude-sonnet-4-20250514", "anthropic")
    elif os.getenv("OPENAI_API_KEY"):
        from openai import OpenAI
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        _llm_client_cache = LLMClient(client, "gpt-4o", "openai")
    elif os.getenv("GEMINI_API_KEY"):
        import google.generativeai as genai
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        client = genai.GenerativeModel('gemini-1.5-pro-latest')
        _llm_client_cache = LLMClient(client, None, "gemini")
    else:
        raise ValueError("No API keys configured.")
    
    return _llm_client_cache


def fetch_js(path: str) -> str:
    """Fetch JavaScript from URL or local file."""
    if path.startswith(("http://", "https://")):
        response = get_http_session().get(path, timeout=30)
        response.raise_for_status()
        return response.text
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()


def find_sinks_regex(code: str) -> List[str]:
    """Fast regex-based sink detection with line numbers."""
    sinks = []
    lines = code.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        for pattern, sink_type in SINK_PATTERNS:
            if pattern.search(line):
                sinks.append(f"{sink_type} at line {line_num}")
    
    return sinks


def find_sinks_ast(code: str) -> List[str]:
    """AST-based sink detection for complex patterns."""
    import esprima
    sinks = []
    
    try:
        tree = esprima.parseScript(code, tolerant=True, loc=True)
    except Exception:
        return sinks
    
    def get_line(node: Any) -> str:
        if hasattr(node, 'loc') and node.loc:
            return str(node.loc.start.line)
        return '?'
    
    def walk(node: Any) -> None:
        if not hasattr(node, 'type'):
            return
        
        if node.type == 'CallExpression':
            callee = node.callee
            if hasattr(callee, 'name') and callee.name in ('eval', 'Function'):
                sinks.append(f"{callee.name}() call at line {get_line(node)}")
            elif hasattr(callee, 'property'):
                prop_name = getattr(callee.property, 'name', '')
                if prop_name in ('write', 'writeln'):
                    sinks.append(f"document.{prop_name}() at line {get_line(node)}")
                elif prop_name == 'postMessage':
                    sinks.append(f"postMessage() at line {get_line(node)}")
        
        elif node.type == 'AssignmentExpression':
            if hasattr(node.left, 'property'):
                prop_name = getattr(node.left.property, 'name', '')
                if prop_name in ('innerHTML', 'outerHTML'):
                    sinks.append(f"{prop_name} assignment at line {get_line(node)}")
        
        for key in dir(node):
            if key.startswith('_'):
                continue
            child = getattr(node, key, None)
            if isinstance(child, list):
                for item in child:
                    if hasattr(item, 'type'):
                        walk(item)
            elif hasattr(child, 'type'):
                walk(child)
    
    walk(tree)
    return sinks


def basic_analysis(code: str) -> Tuple[str, List[str], List[Dict], List[str]]:
    """Perform basic static analysis on JavaScript code."""
    import jsbeautifier
    
    # Beautify the code
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    beautified = jsbeautifier.beautify(code, opts)
    
    # Use built-in finders (no external dependencies!)
    endpoints = find_links(code)
    secrets = find_secrets(code)
    
    # Find dangerous sinks using both regex and AST
    regex_sinks = set(find_sinks_regex(beautified))
    ast_sinks = set(find_sinks_ast(beautified))
    sinks = list(regex_sinks | ast_sinks)
    
    return beautified, endpoints, secrets, sinks


def chunk_code(code: str, max_chars: int = 20000) -> List[str]:
    """Split code into chunks at line boundaries."""
    if len(code) <= max_chars:
        return [code]
    
    chunks = []
    lines = code.split('\n')
    current_chunk = []
    current_size = 0
    
    for line in lines:
        line_len = len(line) + 1
        
        if current_size + line_len > max_chars and current_chunk:
            chunks.append('\n'.join(current_chunk))
            current_chunk = []
            current_size = 0
        
        current_chunk.append(line)
        current_size += line_len
    
    if current_chunk:
        chunks.append('\n'.join(current_chunk))
    
    return chunks


def llm_call(llm: LLMClient, prompt: str) -> str:
    """Unified LLM call handler."""
    try:
        if llm.provider == "anthropic":
            resp = llm.client.messages.create(
                model=llm.model,
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}]
            )
            return resp.content[0].text
        elif llm.provider == "openai":
            resp = llm.client.chat.completions.create(
                model=llm.model,
                messages=[{"role": "user", "content": prompt}]
            )
            return resp.choices[0].message.content
        elif llm.provider == "gemini":
            resp = llm.client.generate_content(prompt)
            return resp.text
    except Exception as e:
        return f"LLM error: {str(e)}"


def analyze_chunk(args: Tuple[LLMClient, str, int]) -> Tuple[int, str]:
    """Analyze a single chunk."""
    llm, chunk, idx = args
    prompt = f"""Analyze this JS chunk for bug bounty insights:
- Hidden/admin endpoints
- Hardcoded secrets (test vs prod context)
- Client-side vulns (DOM XSS sinks, insecure postMessage, client-only auth)
- Auth bypass potential
- Business logic flaws

Chunk:
{chunk}

Output structured Markdown with severity ratings."""
    
    result = llm_call(llm, prompt)
    return idx, result


def llm_analyze(beautified: str, max_workers: int = 3) -> str:
    """LLM-powered deep analysis with parallel chunk processing."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    llm = get_llm_client()
    chunks = chunk_code(beautified)
    
    if len(chunks) == 1:
        _, result = analyze_chunk((llm, chunks[0], 0))
        return result
    
    insights = [None] * len(chunks)
    chunk_args = [(llm, chunk, i) for i, chunk in enumerate(chunks)]
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(analyze_chunk, args): args[2] for args in chunk_args}
        for future in as_completed(futures):
            idx, result = future.result()
            insights[idx] = result
    
    combined = "\n---\n".join(filter(None, insights))
    sum_prompt = f"""Synthesize these chunk analyses into one cohesive bug bounty report.
Deduplicate findings, prioritize by severity, and highlight the most critical issues.

Chunk Insights:
{combined}

Output a structured Markdown report."""
    
    return llm_call(llm, sum_prompt)


def generate_report(result: AnalysisResult, json_out: bool = False) -> str:
    """Generate final report in Markdown or JSON format."""
    if json_out:
        return json.dumps({
            "input": result.input_path,
            "endpoints": result.endpoints,
            "secrets": result.secrets,
            "sinks": result.sinks,
            "llm_insights": result.llm_insights,
            "error": result.error
        }, indent=2)
    
    sections = [f"# JS Intel Report: {result.input_path}\n"]
    
    if result.error:
        sections.append(f"## Error\n{result.error}\n")
    
    sections.append("## Endpoints")
    if result.endpoints:
        sections.append("\n".join(f"- `{ep}`" for ep in result.endpoints))
    else:
        sections.append("_No endpoints found_")
    
    sections.append("\n## Secrets")
    if result.secrets:
        sections.append("```json\n" + json.dumps(result.secrets, indent=2) + "\n```")
    else:
        sections.append("_No secrets detected_")
    
    sections.append("\n## Potential Sinks")
    if result.sinks:
        sections.append("\n".join(f"- {sink}" for sink in result.sinks))
    else:
        sections.append("_No obvious sinks detected_")
    
    sections.append("\n## LLM Deep Analysis")
    sections.append(result.llm_insights if result.llm_insights else "_Analysis unavailable_")
    
    return "\n".join(sections)


def init_reports_dir() -> None:
    """Initialize reports directory if it doesn't exist."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def load_history() -> List[Dict[str, Any]]:
    """Load report history from JSON file."""
    init_reports_dir()
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    return []


def save_history(history: List[Dict[str, Any]]) -> None:
    """Save report history to JSON file."""
    init_reports_dir()
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=2)


def add_to_history(input_path: str, report_path: Path, report_type: str, 
                   endpoints_count: int, sinks_count: int, secrets_count: int) -> None:
    """Add a report entry to history."""
    history = load_history()
    # Store absolute path for reliability
    report_path_str = str(report_path.resolve())
    
    entry = {
        "id": len(history) + 1,
        "timestamp": datetime.now().isoformat(),
        "input": input_path,
        "report_file": report_path_str,
        "type": report_type,
        "endpoints": endpoints_count,
        "sinks": sinks_count,
        "secrets": secrets_count
    }
    history.append(entry)
    save_history(history)


def view_history() -> None:
    """Display report history."""
    history = load_history()
    
    if not history:
        print("\n  No reports in history yet.")
        return
    
    print("\n" + "═" * 80)
    print("  Report History")
    print("═" * 80)
    print(f"\n  {'ID':<4} {'Timestamp':<20} {'Input':<30} {'Endpoints':<10} {'Sinks':<8} {'Secrets':<8}")
    print("  " + "-" * 78)
    
    for entry in reversed(history[-20:]):  # Show last 20
        timestamp = entry.get("timestamp", "")[:19].replace("T", " ")
        input_path = entry.get("input", "")[:28]
        if len(input_path) > 28:
            input_path = input_path[:25] + "..."
        print(f"  {entry.get('id', 0):<4} {timestamp:<20} {input_path:<30} "
              f"{entry.get('endpoints', 0):<10} {entry.get('sinks', 0):<8} {entry.get('secrets', 0):<8}")
    
    print("\n  💡 Type 'view' or 'show' to see full report details, or use report ID")


def view_report() -> None:
    """View a specific report by ID."""
    import click
    
    history = load_history()
    if not history:
        print("\n  No reports in history yet.")
        return
    
    view_history()
    print()
    
    try:
        report_id = click.prompt("Enter report ID to view", type=int)
        entry = next((e for e in history if e.get("id") == report_id), None)
        
        if not entry:
            print(f"\n  ✗ Report ID {report_id} not found.")
            return
        
        report_file = entry["report_file"]
        report_path = Path(report_file)
        
        if not report_path.exists():
            print(f"\n  ✗ Report file not found: {report_path}")
            return
        
        print(f"\n  {'═' * 80}")
        print(f"  Report #{report_id}: {entry.get('input', '')}")
        print(f"  {'═' * 80}\n")
        
        # Display report content
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
            print(content)
        
        print(f"\n  {'═' * 80}")
        input("\n  Press Enter to continue...")
        
    except (ValueError, KeyboardInterrupt):
        print("\n  Cancelled.")


def clear_history() -> None:
    """Clear all report history."""
    import click
    
    history = load_history()
    if not history:
        print("\n  No history to clear.")
        return
    
    count = len(history)
    if click.confirm(f"\n  ⚠ Delete all {count} report(s) from history? This cannot be undone.", default=False):
        if HISTORY_FILE.exists():
            HISTORY_FILE.unlink()
        print(f"\n  ✓ Cleared {count} report(s) from history.")
        print("  Note: Report files are still saved in the reports directory.")


def show_help() -> None:
    """Display help information with all available commands."""
    help_text = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                              JSpy Commands Help                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

  QUICK COMMANDS (type any of these):
  
  📁 ANALYZE:
     analyze, file, single, 1
        → Analyze single JS file or URL
        Example: file → https://target.com/app.js
    
     dir, folder, directory, 2
        → Analyze directory (recursive)
        Example: dir → ./scraped_js/
  
  ⚙️  CONFIG:
     config, keys, api, 3
        → Configure/update LLM API keys (Anthropic/OpenAI/Gemini)
    
     clear-keys, remove-keys, 9
        → Clear all API keys
  
  📊 REPORTS:
     reports, history, list, ls, 4
        → View report history (last 20)
    
     view, show, open, 5
        → View specific report by ID
    
     clear, 6
        → Clear report history
  
  ℹ️  HELP:
     help, h, ?, commands, 7
        → Show this help
  
     menu
        → Show command menu
  
     exit, quit, q, 8
        → Exit JSpy

  EXAMPLES:
    JSpy> file
    JSpy> https://target.com/app.js
    
    JSpy> reports
    JSpy> view
    JSpy> 5
    
    JSpy> dir
    JSpy> ./scraped_js/

  REPORT STORAGE:
  • Reports saved to: ~/.jspy/reports/
  • History file: ~/.jspy/history.json
  • Reports include: endpoints, secrets, vulnerability sinks, LLM insights

  TIPS:
  • Type commands directly (e.g., 'reports', 'file', 'help')
  • Use numbers (1-9) or text commands - both work!
  • Commands are case-insensitive
  • Use JSON output for automation (when prompted)
  • API keys are saved automatically - no need to re-enter each time

═══════════════════════════════════════════════════════════════════════════════
"""
    print(help_text)
    input("  Press Enter to continue...")


def process_single_file(file_path: str) -> AnalysisResult:
    """Process a single JS file and return analysis result."""
    result = AnalysisResult(input_path=file_path)
    
    try:
        code = fetch_js(file_path)
        beautified, endpoints, secrets, sinks = basic_analysis(code)
        
        result.endpoints = endpoints
        result.secrets = secrets
        result.sinks = sinks
        result.llm_insights = llm_analyze(beautified)
    except Exception as e:
        result.error = str(e)
    
    return result


def process_input(input_path: str, output: Optional[str] = None, json_out: bool = False, 
                  parallel_files: int = 4) -> None:
    """Process single file, URL, or directory."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    init_reports_dir()
    
    if os.path.isdir(input_path):
        js_files = glob.glob(os.path.join(input_path, '**/*.js'), recursive=True)
    else:
        js_files = [input_path]
    
    if not js_files:
        print("No JS files found.")
        return
    
    print(f"Processing {len(js_files)} file(s)...")
    results: List[AnalysisResult] = []
    
    if len(js_files) == 1:
        results.append(process_single_file(js_files[0]))
    else:
        with ThreadPoolExecutor(max_workers=parallel_files) as executor:
            futures = {executor.submit(process_single_file, f): f for f in js_files}
            for i, future in enumerate(as_completed(futures), 1):
                file_path = futures[future]
                result = future.result()
                results.append(result)
                print(f"[{i}/{len(js_files)}] Processed: {file_path}")
    
    reports = [generate_report(r, json_out) for r in results]
    separator = ",\n" if json_out else "\n\n---\n\n"
    
    if json_out and len(reports) > 1:
        full_report = "[\n" + separator.join(reports) + "\n]"
    else:
        full_report = separator.join(reports)
    
    # Generate report filename with timestamp
    if output is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        input_name = os.path.basename(input_path).replace(".js", "").replace("/", "_").replace("\\", "_")[:30]
        ext = ".json" if json_out else ".md"
        output = REPORTS_DIR / f"{timestamp}_{input_name}{ext}"
    else:
        # If user provided a filename, save to reports directory
        output = REPORTS_DIR / os.path.basename(output)
    
    # Save report
    with open(output, "w", encoding="utf-8") as f:
        f.write(full_report)
    
    # Add to history
    total_endpoints = sum(len(r.endpoints) for r in results)
    total_sinks = sum(len(r.sinks) for r in results)
    total_secrets = sum(len(r.secrets) for r in results)
    report_type = "directory" if os.path.isdir(input_path) else "file"
    
    add_to_history(
        input_path,
        output,
        report_type,
        total_endpoints,
        total_sinks,
        total_secrets
    )
    
    print(f"\n✓ Report saved: {output}")
    print(f"  - Files analyzed: {len(js_files)}")
    print(f"  - Total endpoints: {total_endpoints}")
    print(f"  - Total sinks: {total_sinks}")
    print(f"  - Total secrets: {total_secrets}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN MENU
# ══════════════════════════════════════════════════════════════════════════════

def parse_command(user_input: str) -> int:
    """Parse user input (number or command) to menu choice."""
    user_input = user_input.strip().lower()
    
    # Command mappings
    commands = {
        # Analyze commands
        "analyze": 1, "analyze-file": 1, "file": 1, "single": 1, "1": 1,
        "analyze-dir": 2, "directory": 2, "dir": 2, "folder": 2, "2": 2,
        
        # Config commands
        "config": 3, "configure": 3, "api": 3, "keys": 3, "key": 3, "3": 3,
        "clear-keys": 9, "remove-keys": 9, "delete-keys": 9, "9": 9,
        
        # Report commands
        "reports": 4, "report": 4, "history": 4, "list": 4, "ls": 4, "4": 4,
        "view": 5, "view-report": 5, "show": 5, "open": 5, "5": 5,
        "clear": 6, "clear-history": 6, "delete-history": 6, "6": 6,
        
        # Help/Exit
        "help": 7, "h": 7, "?": 7, "commands": 7, "7": 7,
        "exit": 8, "quit": 8, "q": 8, "8": 8,
        "menu": -1,  # Special: show menu
    }
    
    return commands.get(user_input, 0)


def show_menu() -> int:
    """Display interactive menu and get user command."""
    import click
    
    print("\n┌─────────────────────────────────────────────────────────┐")
    print("│                    Commands Menu                        │")
    print("├─────────────────────────────────────────────────────────┤")
    print("│  1 / analyze, file    - Analyze single JS (URL or file)  │")
    print("│  2 / dir, folder      - Analyze directory (recursive)   │")
    print("│  3 / config, keys     - Configure/update API keys       │")
    print("│  4 / reports, history - View report history             │")
    print("│  5 / view, show       - View specific report            │")
    print("│  6 / clear            - Clear history                   │")
    print("│  7 / help, ?          - Show help                        │")
    print("│  8 / exit, quit       - Exit                            │")
    print("│  9 / clear-keys       - Clear all API keys              │")
    print("└─────────────────────────────────────────────────────────┘")
    
    user_input = click.prompt("Enter command or number", default="help").strip()
    return parse_command(user_input)


def main_menu() -> None:
    """Main menu loop."""
    import click
    import keyring
    global _llm_client_cache
    
    print(BANNER)
    print("\n  💡 Type commands directly: 'reports', 'file', 'help', 'menu', etc.")
    print("  💡 Or use numbers: 1-9. Type 'help' for all commands.\n")
    
    while True:
        user_input = click.prompt("JSpy>", default="").strip()
        
        if not user_input:
            user_input = "menu"
        
        choice = parse_command(user_input)
        
        if choice == 1:
            input_path = click.prompt("\nEnter JS URL or file path")
            json_out = click.confirm("JSON output?", default=False)
            process_input(input_path, None, json_out)
            
        elif choice == 2:
            input_dir = click.prompt("\nEnter directory path")
            json_out = click.confirm("JSON output?", default=False)
            process_input(input_dir, None, json_out)
            
        elif choice == 3:
            _llm_client_cache = None
            setup_api_credentials(force=False)  # Will prompt if keys exist
            
        elif choice == 4:
            view_history()
            input("\n  Press Enter to continue...")
            
        elif choice == 5:
            view_report()
            
        elif choice == 6:
            clear_history()
            
        elif choice == 7:
            show_help()
            
        elif choice == 8:
            print("\n  Goodbye! Happy hunting! 🎯\n")
            break
            
        elif choice == 9:
            _llm_client_cache = None
            clear_api_keys()
            
        elif choice == -1:
            # Show menu
            show_menu()
            continue
        else:
            print(f"  ✗ Unknown command: '{user_input}'")
            print("  Type 'help' or '?' to see all commands, or 'menu' to show the menu.")


def main() -> None:
    """Main entry point."""
    if check_first_run():
        if not run_setup_wizard():
            sys.exit(1)
    else:
        print(BANNER)
    
    main_menu()


if __name__ == "__main__":
    main()
