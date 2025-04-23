from fastapi import FastAPI, Request
import httpx
import base64
import hashlib
import re
import json

app = FastAPI()

def compute_sha256_base64(input_string):
    hash_bytes = hashlib.sha256(input_string.encode()).digest()
    return base64.b64encode(hash_bytes).decode()

def get_hex(s):
    return int(s[s.index('(') + 3:-1] if '(' in s else s, 16)

def gen_request_hash(encoded_hash):
    try:
        decoded_str = base64.b64decode(encoded_hash).decode()
        string_array_match = re.search(r"=\[([^\]]*)\]", decoded_str)
        if not string_array_match:
            raise Exception("String array not found")
        string_array = [s.strip().strip("'") for s in string_array_match.group(1).split(",")]

        offset_match = re.search(r"0x([0-9a-fA-F]+);let", decoded_str)
        offset = int(offset_match.group(1), 16) if offset_match else None

        shift_offset = None
        for pattern, keyword in [
            (r"document\[[^(]*\(0x([0-9a-fA-F]+)\)\]", "createElement"),
            (r"'client_hashes':\[navigator\[[^(]*\(0x([0-9a-fA-F]+)\)\]", "userAgent"),
            (r"0x([0-9a-fA-F]+)\)\);return\s", "div")
        ]:
            match = re.search(pattern, decoded_str)
            if match:
                index = get_hex(match.group(1))
                origin = string_array.index(keyword)
                shift_offset = origin - (index - offset)
                break

        if shift_offset is None:
            raise Exception("Shift offset not found")

        server_match = re.search(r"'server_hashes':\[([^,]+),(.+?)\]", decoded_str)
        if not server_match:
            raise Exception("Server hashes not found")

        def resolve_value(v):
            v = v.strip()
            if v.startswith("'"):
                return v.strip("'")
            else:
                index = get_hex(v)
                origin = (index - offset + shift_offset + len(string_array)) % len(string_array)
                return string_array[origin]

        server_hashes = [resolve_value(server_match.group(1)), resolve_value(server_match.group(2))]

        inner_html_match = re.search(r"=([^,;]+),String", decoded_str)
        if not inner_html_match:
            raise Exception("innerHTML not found")
        inner_html_raw = inner_html_match.group(1).strip()
        inner_html = resolve_value(inner_html_raw)

        inner_html_data = {
            "<div><div></div><div></div": 99,
            "<p><div></p><p></div": 128,
            "<br><div></br><br></div": 92,
            "<li><div></li><li></div": 87
        }

        if inner_html not in inner_html_data:
            raise Exception("Unknown inner html pattern")

        inner_html_len = inner_html_data[inner_html]

        number_match = re.search(r"String\(0x([0-9a-fA-F]+)\+", decoded_str)
        extracted_number = int(number_match.group(1), 16) if number_match else None

        user_agent = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36"
        user_agent_hash = compute_sha256_base64(user_agent)
        number_hash = compute_sha256_base64(str(extracted_number + inner_html_len))

        result = {
            "server_hashes": server_hashes,
            "client_hashes": [user_agent_hash, number_hash],
            "signals": {}
        }

        return base64.b64encode(json.dumps(result).encode()).decode()

    except Exception as e:
        return f"Error: {str(e)}"

@app.get("/chat")
async def chat(message: str = "hi"):
    headers1 = {
        "authority": "duckduckgo.com",
        "accept": "*/*",
        "referer": "https://duckduckgo.com/",
        "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36",
        "x-vqd-accept": "1"
    }

    async with httpx.AsyncClient() as client:
        r = await client.get("https://duckduckgo.com/duckchat/v1/status", headers=headers1)
        vqd = r.headers.get("x-vqd-4")
        vqd_hash_raw = r.headers.get("x-vqd-hash-1")
        hash1 = gen_request_hash(vqd_hash_raw)

        headers2 = {
            **headers1,
            "content-type": "application/json",
            "x-fe-version": "serp_20250411_150028_ET-227034fa144d75d4af83",
            "x-vqd-4": vqd,
            "x-vqd-hash-1": hash1
        }

        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": message}]
        }

        r2 = await client.post("https://duckduckgo.com/duckchat/v1/chat", headers=headers2, json=payload)
        return r2.text
