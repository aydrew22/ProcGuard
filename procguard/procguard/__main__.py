import sys


def main() -> None:
    if sys.platform == "win32":  # crisp text on high-DPI Windows screens
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    try:
        import tkinter  # noqa: F401
    except ImportError:
        sys.exit("Tkinter is missing. On macOS use the python.org installer or `brew install python-tk`; "
                 "on Debian/Ubuntu run `sudo apt install python3-tk`.")
    from .gui import run
    run(demo="--demo-alerts" in sys.argv)


if __name__ == "__main__":
    main()
