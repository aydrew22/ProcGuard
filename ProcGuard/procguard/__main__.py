"""Launch ProcGuard with python -m procguard."""
import argparse

from .gui import run


def main():
    parser = argparse.ArgumentParser(description="ProcGuard process risk monitor")
    parser.add_argument("--demo-alerts", action="store_true",
                        help="Show simulated high/medium-risk entries, including a resource-heavy helper")
    args = parser.parse_args()
    run(demo=args.demo_alerts)


if __name__ == "__main__":
    main()
