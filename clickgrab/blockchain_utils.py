import base64
import os
import subprocess
import tempfile
from typing import Dict, List, Tuple, Set
import requests
import re
from Crypto.Hash import keccak

try:
    from .models import CommonPatterns
except ImportError:
    from models import CommonPatterns

import logging

logger = logging.getLogger(__name__)

def run_synchrony(js_code: str, timeout: int = 10) -> str:
    """
    Executes Synchrony CLI to debofuscate JavaScript code
    """
    tmp_in_path = None
    tmp_out_path = None

    try:
        # Create temporary files for input and output
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.js', delete=False, encoding='utf-8') as tmp_in:
            tmp_in.write(js_code)
            tmp_in_path = tmp_in.name

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.js', delete=False, encoding='utf-8') as tmp_out:
            tmp_out_path = tmp_out.name

        # Execute synchrony specifying input and output flags
        # Synchrony syntax: synchrony deobfuscate input.js -o output.js
        cmd = ['synchrony', 'deobfuscate', tmp_in_path, '-o', tmp_out_path]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Read the clean deobfuscated JS from the output file
        if os.path.exists(tmp_out_path) and os.path.getsize(tmp_out_path) > 0:
            with open(tmp_out_path, 'r', encoding='utf-8') as f:
                deobfuscated_code = f.read().strip()

            if deobfuscated_code:
                logger.info("Successfully deobfuscated JS payload using Synchrony.")
                return deobfuscated_code

        logger.warning(f"Synchrony did not write output code. Stderr: {result.stderr.strip()}")

    except subprocess.TimeoutExpired:
        logger.error(f"Synchrony execution timed out after {timeout} seconds.")
    except FileNotFoundError:
        logger.error("Synchrony executable not found! Ensure 'npm install -g deobfuscator' is installed.")
    except Exception as e:
        logger.error(f"Unexpected error running Synchrony: {e}")
    finally:
        # Cleanup temporary files
        for path in (tmp_in_path, tmp_out_path):
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

    return js_code

def smart_deobfuscate(script_content: str) -> str:
    """
    Tiered Deobfuscator Pipeline:
    1. Checks if script is heavily obfuscated using fast regex heuristics.
    2. If YES -> passes to webcrack for full unrolling.
    3. If NO  -> skips heavy subprocess and returns raw script immediately.
    """
    logger.info("Detected JS-Obfuscator signature. Triggering webcrack pipeline...")
    deobfuscated_script = run_synchrony(script_content, timeout=5)
    with open("deobfuscated_sample.js", "w", encoding="utf-8") as f:
        f.write(deobfuscated_script)
    return deobfuscated_script

def extract_valid_smart_contract(text) -> str | None:
    pattern = r"0x[a-fA-F0-9]{40}"
    raw_addresses = re.findall(pattern, text)

    valid_addresses = set()
    for addr in raw_addresses:
        addr_lower = addr.lower()
        # Filter zero-addresses, dead burner addresses, and standard systemic dummies
        if not addr_lower.startswith(
                "0x000000000000000000000") and addr_lower != "0x000000000000000000000000000000000000dead":
            valid_addresses.add(addr)

    extracted_contracts = list(valid_addresses)

    if extracted_contracts:
        logger.info(f"Valid smart contract extracted: {extracted_contracts[0]}")
        return extracted_contracts[0]

    logger.warning("No valid smart contract addresses found in text")
    return None

def compute_keccak_selector(signature: str) -> str:
    """Calculates 4-byte EVM selector using standard Keccak-256."""
    k = keccak.new(digest_bits=256)
    k.update(signature.encode("utf-8"))
    return "0x" + k.hexdigest()[:8]


def extract_function_selectors(text) -> list[dict]:
    """
    Uses multiple heuristics to identify function selectors:
    1. eth_call payload data binding
    2. High-level ABI/Ethers signature extraction
    3. Standalone 4-byte hexadecimal constants
    """
    results = []
    seen_selectors = set()

    # High-Level ABI Parsing (Ethers.js / Web3 interface arrays)
    # Matches patterns like: function getActiveScripts() view returns
    abi_pattern = r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)\s*(?:view|pure|returns|public|external)'
    abi_matches = re.findall(abi_pattern, text)

    for func_name, args_raw in abi_matches:
        # Parse canonical signature (e.g., "getActiveScripts()")
        types = []
        if args_raw.strip():
            for arg in args_raw.split(","):
                parts = arg.strip().split()
                if parts:
                    types.append(parts[0])  # take variable type
        canonical_sig = f"{func_name}({','.join(types)})"
        selector = compute_keccak_selector(canonical_sig)

        seen_selectors.add(selector)
        results.append({
            "selector": selector,
            "type": "abi_signature",
            "signature": canonical_sig,
            "known_alias": CommonPatterns.KNOWN_SELECTOR_DB.get(selector, "Unknown Custom Function")
        })

    # RPC Payload Extraction ('data': '0x' + var_or_hex)
    # Locates variables used in data field within eth_call contexts
    rpc_data_pattern = r'["\']?data["\']?\s*:\s*["\'](0x[a-fA-F0-9]{8})["\']|["\']?data["\']?\s*:\s*["\']0x["\']\s*\+\s*([a-zA-Z0-9_$]+)'
    data_matches = re.findall(rpc_data_pattern, text)

    for direct_hex, var_name in data_matches:
        if direct_hex:
            selector = direct_hex.lower()
            if selector not in seen_selectors:
                seen_selectors.add(selector)
                results.append({
                    "selector": selector,
                    "type": "rpc_payload_context",
                    "known_alias": CommonPatterns.KNOWN_SELECTOR_DB.get(selector, "Unknown Custom Selector")
                })
        elif var_name:
            # Find variable declaration (e.g., var _6c5a6e = '38bcdc1c')
            var_pattern = rf'(?:var|let|const)\s+{re.escape(var_name)}\s*=\s*[\'"`]([a-fA-F0-9]{8})[\'"`]'
            var_match = re.search(var_pattern, text)
            if var_match:
                selector = "0x" + var_match.group(1).lower()
                if selector not in seen_selectors:
                    seen_selectors.add(selector)
                    results.append({
                        "selector": selector,
                        "type": "bound_variable_context",
                        "known_alias": CommonPatterns.KNOWN_SELECTOR_DB.get(selector, "Unknown Custom Selector")
                    })

    #  Hex Search (38bcdc1c pattern match)
    standalone_hex_pattern = r'[\'"\`]([a-fA-F0-9]{8})[\'"\`]'
    hex_matches = re.findall(standalone_hex_pattern, text)
    for raw_hex in hex_matches:
        selector = "0x" + raw_hex.lower()
        if selector in CommonPatterns.KNOWN_SELECTOR_DB and selector not in seen_selectors:
            seen_selectors.add(selector)
            results.append({
                "selector": selector,
                "type": "known_signature_fallback",
                "known_alias": CommonPatterns.KNOWN_SELECTOR_DB[selector]
            })

    return results


def pick_correct_selector(selectors_list: list[dict]) -> str | None:
    """
    From a list of found selectors, pick the correct one with the following priority levels:
    1. Known malicious/campaign signatures or RPC payload bound context
    2. Genuine Solidity ABIs (Solidity parameters use types like uint256, string, address, NOT JS variable names like _e518)
    3. Fallback: take the first selector of the list
    """
    # Priority 1
    high_priority = [
        s for s in selectors_list
        if s["type"] in ("known_signature_fallback", "rpc_payload_context", "bound_variable_context")
    ]
    if high_priority:
        return high_priority[0]["selector"]

    # Priority 2
    solidity_types = ("uint", "string", "address", "bytes", "bool", "int")
    valid_abis = [
        s for s in selectors_list
        if s["type"] == "abi_signature" and any(t in s.get("signature", "").lower() for t in solidity_types)
    ]
    if valid_abis:
        return valid_abis[0]["selector"]

    # Fallback if nothing specific matched
    return selectors_list[0]["selector"] if selectors_list else None


def extract_etherhiding_js_patterns(script_content: str) -> tuple[bool, int, dict | None]:
    """
    Extract etherhiding patterns from a JS script content.
    """
    obfuscation_score = 0
    # Check if there's eth_call or some hex strings with some common RPC keyword inside the script
    is_etherhiding = 'eth_call' in script_content or (
            '0x' in script_content and any(kw in script_content for kw in CommonPatterns.COMMON_RPC_KEYWORDS)
    )
    if is_etherhiding:
        obfuscation_score += 5
        obfuscation_indicator = {
            'pattern': 'EtherHiding Signature (eth_call / RPC)',
            'examples': ['EtherHiding RPC pattern detected'],
            'count': 1
        }
        return is_etherhiding, obfuscation_score, obfuscation_indicator
    return is_etherhiding, obfuscation_score, None

def is_base64(decoded_string: str) -> bool:
    # Standard Base64 length must be a multiple of 4
    if len(decoded_string) % 4 != 0:
        return False

    try:
        # Convert string to bytes and attempt decoding with strict validation
        decoded = base64.b64decode(decoded_string, validate=True)

        # Re-encode to verify round-trip consistency (prevents false positives)
        return base64.b64encode(decoded).decode('utf-8') == decoded_string

    except Exception as e:
        return False

def base64_decode(b64_string: str) -> str | None:
    try:
        raw_bytes = base64.b64decode(b64_string)

        # Safely convert to text without raising UnicodeDecodeError
        decoded_text = raw_bytes.decode('utf-8', errors='ignore')
        return decoded_text

    except base64.binascii.Error as e:
        logger.error(f"Invalid Base64 string: {e}")

def decode_payload(raw_hex: str) -> str:
    """
    Strips '0x', converts valid hex bytes to ASCII, and extracts all
    printable JS/HTML code chunks longer than 8 characters.
    """
    clean_hex = raw_hex[2:] if raw_hex.startswith("0x") else raw_hex

    # Ensure even hex character length
    if len(clean_hex) % 2 != 0:
        clean_hex = clean_hex[:-1]  # Drop the dangling odd character

    try:
        raw_bytes = bytes.fromhex(clean_hex)
        # Extract sequences of readable ASCII characters (JS code, URLs, Strings)
        extracted_chunks = re.findall(rb'[\x20-\x7E\s]{8,}', raw_bytes)

        # Clean and filter out empty whitespace chunks
        decoded_hex = [chunk.decode('utf-8').strip() for chunk in extracted_chunks if chunk.decode('utf-8').strip()]
    except Exception as e:
        return f"Decoding error: {str(e)}"

    for i in range(len(decoded_hex)):
        base64_decoded = is_base64(decoded_hex[i])
        if base64_decoded:
            decoded_hex[i] = base64_decode(decoded_hex[i])

    return decoded_hex[0]

def fetch_payload(found_rpcs: List[str], contract_address: str, selector: str, proxies: Dict[str, str] | None) -> Tuple[dict, str]:
    """
    Queries the live smart contract via JSON-RPC eth_call and decodes
    EVM dynamic bytes/string return structures into human-readable code.
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [
            {"to": contract_address, "data": selector},
            "latest"
        ]
    }

    for rpc_url in found_rpcs:
        try:
            res = requests.post(rpc_url, json=payload, timeout=8, proxies=proxies).json()
            raw_hex = res.get("result", "")
            if raw_hex and raw_hex != "0x":
                return {"status": "success", "raw_hex_length": len(raw_hex), "extracted_payload": raw_hex}, rpc_url

        except Exception as e:
            logger.error(f"ERROR: {e}")
            continue
    return {}, ""

VALID_TLDS = {
    "com", "org", "net", "xyz", "io", "co", "info", "biz", "gov",
    "edu", "me", "dev", "app", "tv", "cc", "online", "site", "tech", "link", "ai"
}

def is_valid_url_or_ip(text):
    # Always keep standard URLs
    if text.startswith(("http://", "https://")):
        return True

    # Keep IP addresses (e.g., 127.0.0.1)
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$", text):
        return True

    # Check clear domains against TLD list
    parts = text.split('.')
    if len(parts) >= 2:
        tld = parts[-1].split('/')[0].split(':')[0]  # extract TLD ignoring paths/ports
        if tld in VALID_TLDS:
            return True

    return False

def extract_malicious_url_and_check_next_stage(payload) -> Tuple[Set[str], bool]:
    """
    Extract raw URLs from a decoded Etherhiding payload. If it contains another Blockchain, then it's a multi-stage Etherhiding
    and we need to perform another iteration.
    """
    URL_REGEX = re.compile(r'(?:https?://)?(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:/[^\s"\'\(\)<>]*)?')

    found_urls = set()
    is_last_stage = True
    rpcs_without_proto = [
        rpc.replace("https://", "").replace("http://", "")
        for rpc in CommonPatterns.RPC_ENDPOINTS
    ]
    for match in URL_REGEX.finditer(payload):
        # Clean trailing quotes or standard JS punctuation
        cleaned_url = match.group(0).rstrip("\";',)")

        if not is_valid_url_or_ip(cleaned_url):
            continue

        found_urls.add(cleaned_url)

        # If we have extracted a new RPC endpoint, it means it's a multi-stage Etherhiding
        if cleaned_url in CommonPatterns.RPC_ENDPOINTS or cleaned_url in rpcs_without_proto:
            is_last_stage = False

        # Check if common RPC keywords appear in the extracted URL
        for pattern in CommonPatterns.COMMON_RPC_KEYWORDS:
            if pattern in cleaned_url:
                is_last_stage = False

    return found_urls, is_last_stage