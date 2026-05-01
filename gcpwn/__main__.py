from __future__ import annotations

from gcpwn.cli.main import main


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Interrupted. Exiting.")
        raise SystemExit(130)
