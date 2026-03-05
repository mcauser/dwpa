#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import sys
from urllib import request, error
from hashlib import sha1, pbkdf2_hmac

BASE_API_URL = "https://wpa-sec.stanev.org"

def check_nmcli():
    try:
        subprocess.run(["nmcli", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except Exception:
        sys.exit("ERROR: nmcli not found or not working.")

def unescape_nmcli(s: str) -> str:
    return s.replace(r"\:", ":").replace(r"\\", "\\")

def nmcli_scan():
    print("Scanning for WiFi APs...", end="", flush=True)

    cmd = ["nmcli", "-t", "-e", "yes", "-f", "SSID,SSID-HEX,BSSID,BARS,SECURITY", "dev", "wifi", "list"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.output.decode("utf-8", "replace"))
        sys.exit(f"ERROR: nmcli scan failed with exit code {e.returncode}.")

    lines = out.decode("utf-8", "replace").splitlines()

    nets = []
    for line in lines:
        if not line.strip():
            continue
        parts = re.split(r'(?<!\\):', line)
        # SSID, SSID-HEX, BSSID, BARS, SECURITY
        if len(parts) < 5:
            continue
        # validate SSID
        if len(parts[0]) * 2 != len(parts[1]):
            continue
        # validate BSSID
        if len(parts[2]) != 22:
            continue
        # validate security type
        if "802.1X" in parts[4] or "WPA" not in parts[4] or parts[0] == "":
            continue

        nets.append({
            "ssid": unescape_nmcli(parts[0]),
            "ssid_hex": parts[1],
            "bssid": unescape_nmcli(parts[2]).replace(":", "").lower(),
            "bars": parts[3],
            "security": parts[4]
        })

    print("OK\n")

    if not nets:
        sys.exit("No suitable APs found.")

    return nets


def nmcli_saved():
    print("Loading saved WiFi profiles...", end="", flush=True)

    cmd = ["nmcli", "-t", "-e", "yes", "-f", "NAME,UUID,TYPE", "con", "show"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.output.decode("utf-8", "replace"))
        sys.exit(f"ERROR: nmcli scan failed with exit code {e.returncode}.")

    lines = out.decode("utf-8", "replace").splitlines()

    nets = []
    lc = len(lines)
    c = 0
    for line in lines:
        c += 1
        print(f"\rLoading saved WiFi profiles ({c}/{lc})...", end="", flush=True)

        if not line.strip():
            continue
        parts = re.split(r'(?<!\\):', line)
        if len(parts) < 3:
            continue

        # check for wifi profile
        if parts[2] != '802-11-wireless':
            continue

        cmd = ["nmcli", "-t", "-e", "yes", "-s", "-g", "802-11-wireless.ssid,802-11-wireless-security.psk,802-11-wireless-security.key-mgmt", "con", "show", parts[1]]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            continue

        dlines = out.decode("utf-8", "replace").splitlines()
        if len(dlines) != 3:
            continue

        name = unescape_nmcli(parts[0])
        ssid = unescape_nmcli(dlines[0])
        psk = unescape_nmcli(dlines[1])
        keymgmt = dlines[2]

        # validate SSID
        if len(ssid) == 0:
            continue
        # validate PSK
        if len(psk) < 8:
            continue
        if len(psk) > 64:
            continue
        # validate key-mgmt
        if keymgmt not in ("wpa-psk", "sae"):
            continue

        # compute PMK
        if len(psk) == 64:
            pmk = psk
        else:
            pmk = pbkdf2_hmac("sha1", psk.encode("utf-8"), ssid.encode("utf-8"), 4096, 32).hex()

        nets.append({
            "name": name,
            "ssid": ssid,
            "psk": psk,
            "pmk": pmk
        })

    print("OK\n")

    if not nets:
        sys.exit("No suitable WiFi profiles found.")

    return nets

def post_keys(url: str, keys):
    data = json.dumps(keys).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    req = request.Request(url, data=data, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=10.0) as resp:
            body = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            if "application/json" in ctype:
                return json.loads(body.decode("utf-8", "replace"))
            return {}
    except error.HTTPError as e:
        msg = e.read().decode("utf-8", "replace")
        sys.exit(f"HTTP {e.code} - {msg}")
    except Exception as e:
        sys.exit(f"Request error: {e}")

def merge_nets_results(nets: list[dict], results: dict):
    for n in nets:
        clid = n["key"][:4]
        suffixes = results.get(clid)
        if not suffixes:
            continue
        if n["key"][-8:] in suffixes:
            n["found"] = True
            n["status"] = "LEAKED"

def print_table(data: dict, header: dict, found_key: str):
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    RESET = "\033[0m"

    keys = [k for k in header.keys() if k != found_key]

    col_widths = {}
    for key in header:
        max_content = max(
            [len(str(row.get(header[key], ""))) for row in data],
            default=0
        )
        col_widths[key] = max(len(key), max_content)

    header_line = "  ".join(
        f"{BOLD}{key.ljust(col_widths[key])}{RESET}" for key in header
    )
    print(header_line)
    print("-" * (sum(col_widths.values()) + len(col_widths) * 2))

    for row in data:
        color = RED if row.get(found_key) else GREEN
        line = "  ".join(
            f"{str(row.get(header[key], '')).ljust(col_widths[key])}" for key in keys
        )
        print(f"{color}{line}{RESET}")

    print("-" * (sum(col_widths.values()) + len(col_widths) * 2))

def print_total(nets: dict):
    total = len(nets)
    leaked = sum(1 for r in nets if r.get("found") is True)

    print(f"Leaked networks: {leaked} of {total} ({leaked / total * 100:.0f}%)")


def main():
    ap = argparse.ArgumentParser(
        description="Use NetworkManager information to query wpa-sec, v1.0.0",
        epilog="This program will NOT send any confidential key material to the API. It uses a k-anonymity scheme to protect the privacy."
    )

    subparsers = ap.add_subparsers(dest="mode", required=True, help="Operation mode")
    subparsers.add_parser("scan",
        help="Scan for available WiFi APs",
        description="Scan mode: queries NetworkManager for visible WiFi networks "
        "and submits them to wpa-sec."
    )
    subparsers.add_parser(
        "saved",
        help="Check saved WiFi profiles",
        description="Saved mode: inspects WiFi profiles already stored on this system "
                    "and queries wpa-sec with their information."
    )
    pmk_parser = subparsers.add_parser(
        "pmk",
        help="Check single PMK against wpa-sec",
        description="PMK mode: Manually queries wpa-sec by PMK"
    )
    pmk_parser.add_argument(
        "PMK",
        type=lambda v: v.lower() if re.fullmatch(r"^[0-9a-fA-F]{64}$", v)
            else (_ for _ in ()).throw(argparse.ArgumentTypeError(
            "PMK must be exactly 64 hex characters")),
        help="PMK in 64 hex chars"
    )
    macssid_parser = subparsers.add_parser(
        "macssid",
        help="Check single BSSID+SSID pair against wpa-sec",
        description="MACSSID mode: Manually queries wpa-sec by BSSID+SSID"
    )
    macssid_parser.add_argument(
        "MAC",
        type=lambda v: v.lower() if re.fullmatch(r"^[0-9a-fA-F]{12}$", v)
            else (_ for _ in ()).throw(argparse.ArgumentTypeError(
            "MAC must be exactly 12 hex characters")),
        help="BSSID in 12 hex chars"
    )
    macssid_parser.add_argument(
        "SSID",
        type=lambda v: v if re.fullmatch(r"^.{1,32}$", v)
            else (_ for _ in ()).throw(argparse.ArgumentTypeError(
            "SSID must be betweeen 1 and 32 characters")),
        help="SSID of the network"
    )

    args = ap.parse_args()

    check_nmcli()

    if args.mode == "scan":
        nets = nmcli_scan()
        if len(nets) == 0:
            sys.exit("No suitable APs found.")

        # Compute partial keys
        datak = []
        for n in nets:
            n["key"] = sha1(f"{n['bssid']}{n['ssid_hex'].lower()}".encode("ascii")).hexdigest()
            datak.append(n["key"][:4])
        datak = list(set(datak))

        results = post_keys(f"{BASE_API_URL}/bmacssid", datak)
        if not isinstance(results, dict):
            results = {}

        merge_nets_results(nets, results)

        header = {
                  "BSSID": "bssid",
                  "SSID": "ssid",
                  "BARS": "bars",
                  "SEC": "security",
                  "STATUS": "status",
                 }

        print_table(nets, header, "found")
        print_total(nets)

    if args.mode == "saved":
        nets = nmcli_saved()
        if len(nets) == 0:
            sys.exit("No suitable profiles found.")

        # Compute partial keys
        for n in nets:
            n["key"] = sha1(n["pmk"].encode("ascii")).hexdigest()

        datak = list({n["key"][:4] for n in nets})

        results = post_keys(f"{BASE_API_URL}/bpmk", datak)
        if not isinstance(results, dict):
            results = {}

        merge_nets_results(nets, results)

        header = {
                  "PROFILE": "name",
                  "SSID": "ssid",
                  "STATUS": "status",
                 }

        print_table(nets, header, "found")
        print_total(nets)

    if args.mode == "pmk":
        nets = [{"key": sha1(args.PMK.encode("ascii")).hexdigest()}]
        datak = [nets[0]["key"][:4]]

        results = post_keys(f"{BASE_API_URL}/bpmk", datak)
        if not isinstance(results, dict):
            results = {}

        merge_nets_results(nets, results)

        if nets[0].get("found") is None:
            print("Not leaked")
            return

        header = {
                  "STATUS": "status",
                 }

        print_table(nets, header, "found")

    if args.mode == "macssid":
        nets = [{"key": sha1(f"{args.MAC}{args.SSID.encode('utf-8').hex()}".encode("ascii")).hexdigest()}]
        datak = [nets[0]["key"][:4]]

        results = post_keys(f"{BASE_API_URL}/bmacssid", datak)
        if not isinstance(results, dict):
            results = {}

        merge_nets_results(nets, results)

        if nets[0].get("found") is None:
            print("Not leaked")
            return

        header = {
                  "STATUS": "status",
                 }

        print_table(nets, header, "found")


if __name__ == "__main__":
    main()
