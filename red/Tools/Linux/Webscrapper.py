#!/usr/bin/env python3
import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from urllib.parse import urlparse

# Names wordlist for validating tokens.
NAMES_WORDLIST = "/usr/share/seclists/Usernames/Names/names.txt"

email_pattern = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
name_pattern = re.compile(r"^[A-Z][a-z]{1,}$")
# A run of 2+ consecutive capitalized words, e.g. "Bjoern Kimminich"
name_run_pattern = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b")
tag_pattern = re.compile(r"<[^>]+>")
script_style_pattern = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.DOTALL | re.I)

STOPWORDS = {
    "home", "about", "contact", "privacy", "policy", "terms", "login", "logout",
    "register", "search", "menu", "services", "products", "company", "team",
    "careers", "news", "blog", "support", "help", "faq", "account", "settings",
    "profile", "dashboard", "welcome", "cookie", "cookies", "copyright", "rights",
    "reserved", "subscribe", "newsletter", "email", "password", "username", "submit",
    "download", "upload", "share", "follow", "learn", "more", "read", "click", "here",
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "page", "site", "website", "online", "please", "thank", "thanks",
}


def require(tool):
    if not shutil.which(tool):
        sys.exit(f"Error: '{tool}' not found on PATH.")
    print(f"[+] {tool} found on PATH")


def load_name_dictionary():
    if not os.path.isfile(NAMES_WORDLIST):
        print(f"[!] Names wordlist not found at {NAMES_WORDLIST}; skipping validation")
        return None
    with open(NAMES_WORDLIST, encoding="utf-8", errors="ignore") as f:
        return {line.strip().lower() for line in f if line.strip()}


def fetch_page_text(url):
    """Fetch a URL and return visible text with word order preserved (tags stripped)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[!] Could not fetch page text for adjacency pairing: {e}")
        return ""
    raw = script_style_pattern.sub(" ", raw)   # drop JS/CSS bodies
    raw = tag_pattern.sub(" ", raw)            # drop remaining tags
    return html.unescape(raw)


def pairs_from_text(text, name_dict):
    """
    Find runs of consecutive capitalized words and emit adjacent First/Last pairs.
    A pair is kept unless a token is a stopword. If a names dictionary is present it
    only *promotes* ordering (dict matches listed first);
    """
    pairs, seen = [], set()
    for run in name_run_pattern.findall(text):
        toks = run.split()
        for a, b in zip(toks, toks[1:]):
            if a.lower() in STOPWORDS or b.lower() in STOPWORDS:
                continue
            key = (a, b)
            if key in seen:
                continue
            seen.add(key)
            pairs.append(f"{a} {b}")
    return pairs


def build_usernames(url):
    name_dict = load_name_dictionary()

    # Adjacent pairs from the live page text
    text = fetch_page_text(url)
    pairs = pairs_from_text(text, name_dict)
    print(f"[+] {len(pairs)} adjacent name pairs from page text")

    # Author names from document metadata
    if os.path.isfile("meta.txt"):
        meta_text = open("meta.txt", encoding="utf-8", errors="ignore").read()
        meta_pairs = pairs_from_text(meta_text, name_dict)
        for p in meta_pairs:
            if p not in pairs:
                pairs.append(p)
        print(f"[+] {len(meta_pairs)} pairs from document metadata")

    with open("name_candidates.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(pairs) + "\n")
    print(f"[+] {len(pairs)} first/last combos -> name_candidates.txt")

    if pairs:
        with open("usernames.txt", "w") as f:
            subprocess.run(["username-anarchy", "-i", "name_candidates.txt"], stdout=f)
        print("[+] Username generation finished: usernames.txt")
    else:
        open("usernames.txt", "w").close()
        print("[!] No name pairs generated; usernames.txt is empty")


def append_findings(findings_path):
    if not os.path.isfile(findings_path):
        print(f"[!] {findings_path} not found; skipping")
        return
    with open(findings_path, encoding="utf-8") as source:
        lines = source.readlines()
    with open("usernames.txt", "a", encoding="utf-8") as usernames, \
         open(findings_path, "w", encoding="utf-8") as findings:
        for line in lines:
            emails = email_pattern.findall(line)
            remainder = email_pattern.sub("", line).strip(" \t\r\n,;|:-")
            for email in emails:
                usernames.write(f"{email}\n")
            if remainder:
                findings.write(f"{remainder}\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate word and username lists from a website. Names are auto-extracted from CeWL output.",
        epilog="Example: webscraper.py -url https://example.com -m 5 --subfinder --theHarvester",
    )
    parser.add_argument("-url", "--url", required=True, help="website URL to scrape")
    parser.add_argument("-m", "--min-length", type=int, default=5, help="CeWL minimum word length")
    parser.add_argument("--subfinder", action="store_true", help="Run subfinder on the domain")
    parser.add_argument("--theHarvester", "--theharvester", action="store_true", help="Run theHarvester on the domain")
    return parser.parse_args()


def main():
    args = parse_args()

    # CeWL needs a full URL 
    if "://" not in args.url:
        args.url = "http://" + args.url
    domain = urlparse(args.url).netloc

    require("cewl")
    require("username-anarchy")
    if args.subfinder:
        require("subfinder")
    if args.theHarvester:
        require("theHarvester")

    subprocess.run(["cewl", "-m", str(args.min_length), "-a", "--meta_file", "meta.txt",   "-w", "words.txt", args.url,])
    print("[+] CeWL finished: words.txt (+ meta.txt)")

    build_usernames(args.url)

    if args.subfinder:
        subprocess.run(
            ["subfinder", "-d", domain, "-all", "-o", "subfinder_findings.txt"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        append_findings("subfinder_findings.txt")
        print("[+] Subfinder output processed")

    if args.theHarvester:
        # theHarvester -f writes .json (and .xml), not .txt. Request json, then flatten it.
        subprocess.run(
            ["theHarvester", "-d", domain, "-b", "all", "-l", "100", "-f", "theHarvester_findings"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        json_path = "theHarvester_findings.json"
        if os.path.isfile(json_path):
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
            emails = data.get("emails", [])
            hosts = data.get("hosts", []) + data.get("interesting_urls", [])
            with open("usernames.txt", "a", encoding="utf-8") as u:
                for email in emails:
                    u.write(f"{email}\n")
            with open("theHarvester_findings.txt", "w", encoding="utf-8") as out:
                out.write("\n".join(hosts) + "\n")
            print(f"[+] theHarvester: {len(emails)} emails, {len(hosts)} hosts")
        else:
            print("[!] theHarvester produced no JSON output")


if __name__ == "__main__":
    main()