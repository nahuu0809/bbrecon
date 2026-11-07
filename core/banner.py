"""ANSI color helpers, console formatting, and ASCII banner."""

BANNER = r"""
  ____  ____  ____
 | __ )| __ )|  _ \ ___  ___ ___  _ __
 |  _ \|  _ \| |_) / _ \/ __/ _ \| '_ \
 | |_) | |_) |  _ <  __/ (_| (_) | | | |
 |____/|____/|_| \_\___|\___\___/|_| |_|

  Bug Bounty Reconnaissance & Testing Framework
"""


class C:
    """Namespace for ANSI color codes and formatted console output helpers."""

    # ── Raw codes ─────────────────────────────────────────────────────────────
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    DIM    = "\033[2m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

    # ── Formatted message helpers ─────────────────────────────────────────────
    @classmethod
    def info(cls, msg: str) -> str:
        return f"{cls.CYAN}[*]{cls.RESET} {msg}"

    @classmethod
    def ok(cls, msg: str) -> str:
        return f"{cls.GREEN}[+]{cls.RESET} {msg}"

    @classmethod
    def warn(cls, msg: str) -> str:
        return f"{cls.YELLOW}[!]{cls.RESET} {msg}"

    @classmethod
    def err(cls, msg: str) -> str:
        return f"{cls.RED}[-]{cls.RESET} {msg}"

    @classmethod
    def vuln(cls, msg: str) -> str:
        return f"{cls.RED}{cls.BOLD}[VULN]{cls.RESET} {msg}"

    @classmethod
    def section(cls, title: str) -> str:
        bar = "─" * (len(title) + 4)
        return f"\n{cls.BOLD}{cls.BLUE}┌{bar}┐\n│  {title}  │\n└{bar}┘{cls.RESET}"


def print_banner() -> None:
    print(C.RED + C.BOLD + BANNER + C.RESET)
    print(C.DIM + "  Use only on systems you are authorized to test." + C.RESET + "\n")
