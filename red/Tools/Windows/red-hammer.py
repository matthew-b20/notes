#!/usr/bin/env python3

import argparse
import json
import logging
import shutil
import subprocess
import sys


BANNER = """
            ╔═════════════════════════════════════════════════════╗
            ║                                                     ║
            ║               ██████  ███████ ██████                ║
            ║               ██   ██ ██      ██   ██               ║
            ║               ██████  █████   ██   ██               ║
            ║               ██  ██  ██      ██   ██               ║
            ║               ██   ██ ███████ ██████                ║
            ║                                                     ║
            ║    ██   ██  █████  ██   ██ ██   ██ ███████ ██████   ║
            ║    ██   ██ ██   ██ ███████ ███████ ██      ██   ██  ║
            ║    ███████ ███████ ██ █ ██ ██ █ ██ █████   ██████   ║
            ║    ██   ██ ██   ██ ██   ██ ██   ██ ██      ██  ██   ║
            ║    ██   ██ ██   ██ ██   ██ ██   ██ ███████ ██   ██  ║
            ║                                                     ║
            ║   ░▒▓█ If you can't use a scalpel, use a... █▓▒░    ║
            ╚═════════════════════════════════════════════════════╝
        """

ALL_PROTOCOLS = [
    "smb", "ldap", "winrm", "mssql", "rdp", "ssh", "ftp", "wmi", "nfs", "vnc",
]

log = logging.getLogger("red-hammer")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="red-hammer.py",
        description="Enumerate what an AD account can reach via nxc.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-dc-ip", dest="ip", required=True,
                        metavar="IP", help="Domain Controller IP")
    parser.add_argument("-u", dest="user", default="",
                        metavar="USER", help="Username to check")
    parser.add_argument("-p", dest="password", default="",
                        metavar="PASS", help="Password for that username")
    parser.add_argument("--protocols", default="",
                        metavar="LIST",
                        help="Comma list to limit checks (default: all). "
                             "choices: " + ",".join(ALL_PROTOCOLS))
    parser.add_argument("--winpeas", action="store_true",
                        help="Drop-and-run winPEAS where execution is available")
    parser.add_argument("--peas-path", dest="peas_path", default="",
                        metavar="PATH",
                        help="Path to winPEAS/linPEAS binary (with --winpeas)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose logging")
    return parser


def resolve_protocols(raw: str):
    """Sanitize protocol input"""
    if not raw:
        return list(ALL_PROTOCOLS)
    chosen = [p.strip().lower() for p in raw.split(",") if p.strip()]
    unknown = [p for p in chosen if p not in ALL_PROTOCOLS]
    if unknown:
        print(f"[!] Unknown protocol(s): {','.join(unknown)}", file=sys.stderr)
        return None
    return chosen


def run_nxc(protocol: str, ip: str, user: str, password: str):
    """Run one nxc protocol check and return parsed JSONL rows.

    nxc emits one JSON object per line with --jsonl; we collect them so the
    summary layer can work with structured data instead of scraping text.
    """
    cmd = [
        "netexec", protocol, ip,
        "-u", user, "-p", password,
        "--jsonl",
    ]
    log.debug("running: %s", " ".join(
        cmd[:3] + ["-u", user, "-p", "******", "--jsonl"]))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        log.warning("[%s] timed out", protocol)
        return []

    rows = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            log.debug("[%s] non-json line: %s", protocol, line)
    return rows


def enumerate_protocols(protocols, ip, user, password):
    """Loop every requested protocol; return {protocol: rows}."""
    results = {}
    for protocol in protocols:
        print(f"[*] Checking {protocol} on {ip} ...")
        results[protocol] = run_nxc(protocol, ip, user, password)
    return results


def inspect_ad(ip, user, password):
    """Rich AD inspection over LDAP + BloodHound.

    TODO:
      - ldap3: bind to the DC, enumerate users/groups/GPOs/ACLs,
        adminCount, kerberoastable + AS-REP-roastable accounts, delegation.
      - dnspython: resolve domain FQDN / SRV from the DC IP for a clean bind.
      - bloodhound-python: collect the access-path graph for "what can this
        user actually reach".
    """
    print("[*] AD inspection (ldap3 / BloodHound) — TODO")
    return {}


def can_execute(protocol_results) -> bool:
    """Decide whether we got code-exec anywhere (admin SMB / WinRM login).

    TODO: inspect nxc rows for the admin ('Pwn3d!') / winrm-login markers
    before ever staging a payload.
    """
    return False


def run_winpeas(ip, user, password, peas_path, protocol_results):
    """Gated post-ex: only fires with --winpeas AND a real exec path.

    TODO:
      - pick winPEAS vs linPEAS from the OS field nxc returned.
      - stage via nxc exec module, or impacket/pypsrp upload + run,
        or host over http.server and have the target pull it.
      - stream output back into the loot/report dir.
    """
    if not can_execute(protocol_results):
        print("[!] --winpeas set but no execution path found; skipping.")
        return
    print(f"[*] Would drop-and-run PEAS ({peas_path or 'auto'}) on {ip} — TODO")


def summarize(protocol_results, ad_results) -> None:
    """Final rollup. Swap in `rich` tables here for readable output."""
    print("\n=== red-hammer summary ===")
    for protocol, rows in protocol_results.items():
        print(f"  {protocol:6s}: {len(rows)} result row(s)")
    # TODO: per-protocol access detail, AD findings, exec-capable hosts.


def print_banner() -> None:
    """Print the banner, tolerating consoles that aren't UTF-8 (e.g. cp1252)."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # Py3.7+; no-op if already utf-8
    except (AttributeError, ValueError):
        pass
    try:
        print(BANNER)
    except UnicodeEncodeError:
        # Last resort: strip characters the console can't render.
        enc = sys.stdout.encoding or "ascii"
        print(BANNER.encode(enc, "replace").decode(enc))


def main(argv=None) -> int:
    print_banner()

    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if shutil.which("netexec") is None:
        print("[!] netexec (nxc) not found on PATH — `pipx install netexec`",
              file=sys.stderr)
        return 1

    protocols = resolve_protocols(args.protocols)
    if protocols is None:
        return 1

    protocol_results = enumerate_protocols(
        protocols, args.ip, args.user, args.password,
    )

    ad_results = {}
    if "ldap" in protocols:
        ad_results = inspect_ad(args.ip, args.user, args.password)

    if args.winpeas:
        run_winpeas(
            args.ip, args.user, args.password,
            args.peas_path, protocol_results,
        )

    summarize(protocol_results, ad_results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
