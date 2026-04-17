import sqlite3
import re
import os

# Regex patterns for sensitive data detection
SENSITIVE_PATTERNS = {
    'credit_card': r'\b(?:\d[ -]?){13,16}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'phone': r'\b(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
    'national_id': r'\b\d{3}-\d{2}-\d{4}\b',  # SSN format as example
}

class DLPResult:
    def __init__(self, passed: bool, reason: str = None, matches: list = None):
        self.passed = passed
        self.reason = reason
        self.matches = matches or []

    def __str__(self):
        if self.passed:
            return "DLP Check: PASSED"
        return f"DLP Check: BLOCKED — {self.reason}"


class DLPEngine:
    def __init__(self, db_path: str = 'database/app.db'):
        self.db_path = db_path

    def _load_active_policies(self):
        """Loads all active policies from the database."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                'SELECT blocked_extensions, sensitive_patterns FROM dlp_policies WHERE active = 1'
            ).fetchall()
        return rows

    def _check_extension(self, filepath: str, blocked_extensions: list) -> DLPResult:
        """Checks if a file's extension is blocked."""
        _, ext = os.path.splitext(filepath)
        ext = ext.lower()
        if ext in blocked_extensions:
            return DLPResult(False, f"File extension '{ext}' is blocked by policy")
        return DLPResult(True)

    def _check_content(self, filepath: str, pattern_names: list) -> DLPResult:
        """Scans file content for sensitive data patterns."""
        # Only scan text-based files
        text_extensions = {'.txt', '.csv', '.json', '.xml', '.html', '.md', '.log'}
        _, ext = os.path.splitext(filepath)
        if ext.lower() not in text_extensions:
            return DLPResult(True)

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return DLPResult(False, f"Could not read file for content scan: {e}")

        found_matches = []
        for pattern_name in pattern_names:
            if pattern_name in SENSITIVE_PATTERNS:
                regex = SENSITIVE_PATTERNS[pattern_name]
                matches = re.findall(regex, content)
                if matches:
                    found_matches.append(f"{pattern_name} ({len(matches)} match(es))")

        if found_matches:
            return DLPResult(
                False,
                f"Sensitive content detected: {', '.join(found_matches)}",
                found_matches
            )
        return DLPResult(True)

    def check_file(self, filepath: str) -> DLPResult:
        """
        Main method — runs all active policy checks against a file.
        Returns a DLPResult with passed=True if all checks pass.
        """
        if not os.path.exists(filepath):
            return DLPResult(False, f"File not found: {filepath}")

        policies = self._load_active_policies()
        if not policies:
            return DLPResult(True)  # No policies = allow everything

        for blocked_exts_str, patterns_str in policies:
            # Check extension
            blocked_exts = [e.strip() for e in blocked_exts_str.split(',')]
            ext_result = self._check_extension(filepath, blocked_exts)
            if not ext_result.passed:
                return ext_result

            # Check content
            pattern_names = [p.strip() for p in patterns_str.split(',')]
            content_result = self._check_content(filepath, pattern_names)
            if not content_result.passed:
                return content_result

        return DLPResult(True)