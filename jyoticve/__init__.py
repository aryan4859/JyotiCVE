"""JyotiCVE security monitoring tool."""
from pathlib import Path

from dotenv import load_dotenv

# Explicit project-working-directory lookup; deployment environment wins.
load_dotenv(Path.cwd() / '.env', override=False)
