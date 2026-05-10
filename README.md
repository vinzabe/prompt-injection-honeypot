# Prompt Injection Honeypot

5 fake LLM endpoints posing as juicy enterprise targets (banking, medical,
HR, internal copilot, customer-service). Captures every attacker prompt,
classifies into attack families, and publishes a live threat-intel feed.

Each persona carries a unique **canary token**; if a canary appears in
attacker traffic OR (god forbid) in our own response, we log it.

## Personas

| Path | Pretends to be | Canary |
|---|---|---|
| `/v1/chat/completions` | ACME internal GPT-4 | `CANARY-ALPHA-...` |
| `/api/v2/assistant` | FirstNational bank assistant | `CANARY-BRAVO-...` |
| `/llm/v1/completions` | MedCenter EMR LLM | `CANARY-CHARLIE-...` |
| `/copilot/chat` | AcmeTech dev copilot | `CANARY-DELTA-...` |
| `/hr/api/chat` | GlobalCorp HR bot | `CANARY-ECHO-...` |

## Attack-family classifier

- `system_prompt_extraction`
- `credential_exfiltration`
- `role_play_jailbreak`
- `encoding_obfuscation`
- `multilingual_evasion`
- `ignore_override`
- `recon_probing`
- `data_exfiltration_via_url`
- `xml_html_injection`

## Threat-intel feed

| Endpoint | Format |
|---|---|
| `/feed/threats.json` | full JSON |
| `/feed/threats.stix.json` | STIX 2.1 bundle |
| `/feed/threats.csv` | spreadsheet |
| `/feed/iocs.txt` | plain IOC list |
| `/dashboard` | live web UI |

## Install

```bash
git clone https://github.com/vinzabe/prompt-injection-honeypot.git
cd prompt-injection-honeypot
pip install -r requirements.txt
```

## Configure

```bash
export LLM_BASE_URL="https://your-llm-endpoint/v1"
export LLM_API_KEY="sk-..."
export LLM_MODEL="glm-5.1"
```

## Run

```bash
python -m honeypot.server   # http://localhost:8081
```

## Test

```bash
python tests/test_honeypot.py
```

10/10 tests pass.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability disclosure policy.

## License

MIT — see [LICENSE](./LICENSE).
