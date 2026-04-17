import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_init import init_database
from core.dlp_engine import DLPEngine

def setup():
    init_database()

def test_blocked_extension():
    engine = DLPEngine()
    # Create a dummy exe file
    test_file = 'tests/malware.exe'
    with open(test_file, 'w') as f:
        f.write("this is a fake exe")

    result = engine.check_file(test_file)
    assert not result.passed, "Should have blocked .exe file"
    print(f"Test passed — blocked extension: {result}")

def test_sensitive_content():
    engine = DLPEngine()
    # Create a file with a fake credit card number
    test_file = 'tests/sensitive.txt'
    with open(test_file, 'w') as f:
        f.write("Customer card: 4111 1111 1111 1111\n")

    result = engine.check_file(test_file)
    assert not result.passed, "Should have blocked sensitive content"
    print(f"Test passed — sensitive content detected: {result}")

def test_clean_file():
    engine = DLPEngine()
    # Create a clean file with no sensitive data
    test_file = 'tests/clean.txt'
    with open(test_file, 'w') as f:
        f.write("This is a completely normal document with no sensitive data.")

    result = engine.check_file(test_file)
    assert result.passed, "Clean file should pass DLP check"
    print(f"Test passed — clean file allowed: {result}")

if __name__ == '__main__':
    setup()
    test_blocked_extension()
    test_sensitive_content()
    test_clean_file()