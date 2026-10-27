"""Create (or upgrade) the SQLite database. Safe to run repeatedly — never deletes data.

    python scripts/init_db.py            create/upgrade data/iva.db (or IVA_DB_PATH)
    python scripts/init_db.py --demo     also add one clearly-labelled DEMO scan
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import load_settings  # noqa: E402
from modules.database import SCHEMA_VERSION, Database  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--demo", action="store_true", help="add a demo scan built from fixture data")
    args = parser.parse_args()
    settings = load_settings()
    db = Database(settings.db_path)
    print(f"Database ready at {settings.db_path} (schema v{SCHEMA_VERSION}); {len(db.list_scans())} scan(s) stored.")
    if args.demo:
        from modules.scan_manager import ScanManager
        scan_id = ScanManager(settings, db=db).create_demo_scan()
        print(f"Demo scan created: {scan_id}")


if __name__ == "__main__":
    main()
