#!/usr/bin/env python3
"""Build a realistic DGA training dataset.

Generates DGA domains using real algorithm patterns from known malware families,
combined with legitimate domains from Tranco Top 1M.

This replaces the 550 synthetic samples with 50,000+ realistic ones.

Sources:
- Legitimate: Tranco Top 1M (real internet traffic)
- DGA: Algorithmic generation mimicking real malware families:
  - Random character (Conficker, Murofet, Ramnit)
  - Hex-based (Necurs, Locky)
  - Dictionary-based (Suppobox, Matsnu, Gozi)
  - Wordlist combination (Banjori, CryptoLocker variants)
  - Punycode/IDN abuse
"""

import csv
import hashlib
import json
import os
import random
import string
import sys
from pathlib import Path

DATASET_DIR = Path(__file__).parent.parent / "datasets"
OUTPUT_DIR = DATASET_DIR

# ── Legitimate domain extraction ──

def load_tranco_domains(path, count=25000):
    """Load top N domains from Tranco CSV."""
    domains = []
    with open(path, 'r') as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            if i >= count * 2:  # oversample to filter
                break
            if len(row) >= 2:
                domain = row[1].strip().lower()
                # Extract SLD (second-level domain)
                parts = domain.split('.')
                if len(parts) >= 2:
                    sld = parts[-2] if parts[-1] not in ('co', 'com', 'org', 'net') else parts[-3] if len(parts) > 2 else parts[-2]
                    if len(sld) >= 3 and sld.isascii():
                        domains.append(sld)

    # Deduplicate and take count
    seen = set()
    unique = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique.append(d)
            if len(unique) >= count:
                break
    return unique


# ── DGA domain generation (mimicking real malware families) ──

def gen_random_char(n=5000):
    """Conficker/Murofet/Ramnit style: pure random lowercase."""
    domains = []
    for _ in range(n):
        length = random.randint(8, 24)
        d = ''.join(random.choices(string.ascii_lowercase, k=length))
        domains.append(d)
    return domains

def gen_hex_based(n=3000):
    """Necurs/Locky style: hex characters only."""
    domains = []
    for _ in range(n):
        length = random.randint(10, 32)
        d = ''.join(random.choices('0123456789abcdef', k=length))
        domains.append(d)
    return domains

def gen_consonant_heavy(n=3000):
    """QakBot/Emotet style: consonant-heavy random."""
    consonants = 'bcdfghjklmnpqrstvwxz'
    vowels = 'aeiouy'
    domains = []
    for _ in range(n):
        length = random.randint(8, 18)
        d = []
        for i in range(length):
            if random.random() < 0.15:  # occasional vowel
                d.append(random.choice(vowels))
            else:
                d.append(random.choice(consonants))
        domains.append(''.join(d))
    return domains

def gen_dictionary_based(n=5000):
    """Suppobox/Matsnu/Gozi style: real words combined.
    These are the hardest to detect — they look like legit domains."""
    words = [
        # Common English words used by DGA
        "account", "admin", "analysis", "annual", "archive", "article", "bank",
        "benefit", "board", "business", "campaign", "capital", "center", "change",
        "channel", "check", "claim", "client", "cloud", "commission", "community",
        "company", "complete", "computer", "conference", "control", "council",
        "country", "credit", "current", "customer", "daily", "data", "defense",
        "delivery", "design", "detail", "development", "digital", "direct",
        "document", "economic", "education", "election", "energy", "engine",
        "enterprise", "environment", "event", "exchange", "executive", "express",
        "federal", "finance", "foreign", "forward", "foundation", "general",
        "global", "government", "group", "growth", "guide", "health", "history",
        "house", "human", "impact", "industry", "information", "insurance",
        "international", "internet", "investment", "journal", "justice", "labor",
        "launch", "leader", "legal", "letter", "library", "light", "limited",
        "local", "management", "market", "master", "media", "medical", "member",
        "message", "military", "ministry", "mobile", "model", "modern", "money",
        "monitor", "monthly", "morning", "national", "natural", "network",
        "north", "number", "office", "online", "operation", "order", "original",
        "partner", "patient", "people", "personal", "platform", "player",
        "point", "police", "policy", "political", "popular", "portal", "power",
        "president", "private", "problem", "product", "professional", "program",
        "project", "property", "public", "quality", "question", "radio", "range",
        "record", "region", "release", "report", "research", "resource", "result",
        "review", "right", "royal", "safety", "school", "science", "search",
        "season", "second", "secret", "section", "security", "server", "service",
        "session", "single", "social", "society", "software", "solution", "source",
        "south", "special", "standard", "station", "status", "stock", "storage",
        "strategy", "student", "study", "support", "surface", "survey", "system",
        "target", "technology", "trade", "training", "transfer", "transport",
        "travel", "trust", "union", "united", "update", "value", "version",
        "video", "virtual", "vision", "volume", "weather", "western", "window",
        "worker", "world", "youth",
    ]

    domains = []
    for _ in range(n):
        style = random.random()
        if style < 0.3:
            # Two words concatenated: "monthlyreport", "securityupdate"
            w1 = random.choice(words)
            w2 = random.choice(words)
            domains.append(f"{w1}{w2}")
        elif style < 0.5:
            # Word + digits: "report2847", "server4921"
            w = random.choice(words)
            digits = ''.join(random.choices(string.digits, k=random.randint(2, 5)))
            domains.append(f"{w}{digits}")
        elif style < 0.7:
            # Three words: "globalfinancegroup"
            w1 = random.choice(words)
            w2 = random.choice(words)
            w3 = random.choice(words)
            domains.append(f"{w1}{w2}{w3}")
        elif style < 0.85:
            # Word-word with hyphen: "security-update", "monthly-report"
            w1 = random.choice(words)
            w2 = random.choice(words)
            domains.append(f"{w1}-{w2}")
        else:
            # Word + random suffix: "microsoft-security-a7f3"
            w = random.choice(words)
            suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(3, 6)))
            domains.append(f"{w}-{suffix}")

    return domains

def gen_hash_based(n=3000):
    """CryptoLocker/TorrentLocker style: MD5/SHA1 prefix as domain."""
    domains = []
    for i in range(n):
        seed = f"seed-{i}-{random.randint(0, 999999)}"
        h = hashlib.md5(seed.encode()).hexdigest()
        length = random.randint(8, 16)
        domains.append(h[:length])
    return domains

def gen_mixed_alphanumeric(n=3000):
    """Generic mixed: letters + digits, variable patterns."""
    domains = []
    for _ in range(n):
        length = random.randint(6, 20)
        pattern = random.choice([
            # digit-letter-digit
            lambda: ''.join(random.choice(string.digits) if i % 3 == 0 else random.choice(string.ascii_lowercase) for i in range(length)),
            # blocks: "abc123def456"
            lambda: ''.join(random.choices(string.ascii_lowercase, k=3)) + ''.join(random.choices(string.digits, k=3)) + ''.join(random.choices(string.ascii_lowercase, k=max(length-6, 3))),
            # all lowercase + scattered digits
            lambda: ''.join(random.choice(string.ascii_lowercase + string.digits) if random.random() < 0.3 else random.choice(string.ascii_lowercase) for _ in range(length)),
        ])
        domains.append(pattern())
    return domains


def build_dataset():
    """Build the complete training dataset."""
    print("Building DGA training dataset...")

    # Load legitimate domains
    tranco_path = DATASET_DIR / "top-1m.csv"
    if not tranco_path.exists():
        print(f"ERROR: Tranco file not found at {tranco_path}")
        sys.exit(1)

    legit_domains = load_tranco_domains(tranco_path, count=25000)
    print(f"  Legitimate domains: {len(legit_domains)} (from Tranco Top 1M)")

    # Generate DGA domains from multiple families
    dga_random = gen_random_char(5000)
    dga_hex = gen_hex_based(3000)
    dga_consonant = gen_consonant_heavy(3000)
    dga_dict = gen_dictionary_based(5000)
    dga_hash = gen_hash_based(3000)
    dga_mixed = gen_mixed_alphanumeric(3000)

    # Add phishing domains from OpenPhish if available
    phishing_domains = []
    openphish_path = DATASET_DIR / "openphish_domains.txt"
    if openphish_path.exists():
        with open(openphish_path) as f:
            for line in f:
                d = line.strip()
                if d:
                    parts = d.split('.')
                    if len(parts) >= 2:
                        sld = parts[-2]
                        if len(sld) >= 3:
                            phishing_domains.append(sld)
        print(f"  Phishing domains: {len(phishing_domains)} (from OpenPhish)")

    all_dga = dga_random + dga_hex + dga_consonant + dga_dict + dga_hash + dga_mixed + phishing_domains
    random.shuffle(all_dga)

    # Deduplicate
    seen = set()
    dga_unique = []
    for d in all_dga:
        dl = d.lower()
        if dl not in seen and dl not in set(ld.lower() for ld in legit_domains[:1000]):
            seen.add(dl)
            dga_unique.append(dl)

    print(f"  DGA domains: {len(dga_unique)} (6 families + phishing)")
    print(f"    Random char: {len(dga_random)}")
    print(f"    Hex-based: {len(dga_hex)}")
    print(f"    Consonant-heavy: {len(dga_consonant)}")
    print(f"    Dictionary-based: {len(dga_dict)}")
    print(f"    Hash-based: {len(dga_hash)}")
    print(f"    Mixed alphanum: {len(dga_mixed)}")

    # Build dataset
    dataset = []
    for d in legit_domains:
        dataset.append({"domain": d, "label": 0, "family": "legit"})
    for d in dga_unique:
        family = "unknown"
        if d in dga_random: family = "random_char"
        elif d in dga_hex: family = "hex_based"
        elif d in dga_consonant: family = "consonant_heavy"
        elif d in dga_dict: family = "dictionary_based"
        elif d in dga_hash: family = "hash_based"
        elif d in dga_mixed: family = "mixed_alphanum"
        elif d in phishing_domains: family = "phishing"
        dataset.append({"domain": d, "label": 1, "family": family})

    random.shuffle(dataset)

    # Split 80/20
    split_idx = int(len(dataset) * 0.8)
    train = dataset[:split_idx]
    test = dataset[split_idx:]

    # Save
    output = OUTPUT_DIR / "dga_dataset.json"
    with open(output, 'w') as f:
        json.dump({"train": train, "test": test, "meta": {
            "legit_count": len(legit_domains),
            "dga_count": len(dga_unique),
            "train_count": len(train),
            "test_count": len(test),
            "families": ["legit", "random_char", "hex_based", "consonant_heavy",
                         "dictionary_based", "hash_based", "mixed_alphanum", "phishing"],
            "source_legit": "Tranco Top 1M",
            "source_dga": "Algorithmic generation mimicking real malware families",
        }}, f)

    print(f"\nDataset saved to {output}")
    print(f"  Train: {len(train)} samples")
    print(f"  Test: {len(test)} samples")
    print(f"  Total: {len(dataset)} samples")

    return output


if __name__ == "__main__":
    build_dataset()
