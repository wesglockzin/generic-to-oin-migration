"""
app.py — OIN Migration Tool
Run: .venv/bin/python app.py
Then open: http://localhost:5003
"""
from __future__ import annotations

import glob
import io
import json
import logging
import os
import re as _re
import subprocess
import sys
import zipfile
from pathlib import Path

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("oin")

# ── Action logger — persistent, human-readable, one line per action ──────────
_alog = logging.getLogger("oin.actions")
_alog.setLevel(logging.INFO)
_alog.propagate = False
_ah = logging.FileHandler(Path(__file__).parent / "oin-actions.log", encoding="utf-8")
_ah.setFormatter(logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
_alog.addHandler(_ah)

def _log_action(env: str, action: str, label: str, outcome: str, detail: str = "") -> None:
    _alog.info("%-5s| %-12s| %-40s| %-10s| %s",
               env.upper()[:5], action[:12], label[:40], outcome[:10], detail)

# ── User overrides — persisted decisions (no_oin, review_needed) ─────────────
import sqlite3 as _sqlite3

_OVERRIDES_DB = Path(__file__).parent / "oin-overrides.db"

def _overrides_conn():
    conn = _sqlite3.connect(str(_OVERRIDES_DB))
    conn.row_factory = _sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS overrides (
            app_id   TEXT PRIMARY KEY,
            decision TEXT NOT NULL,
            label    TEXT,
            env      TEXT,
            ts       TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
        )
    """)
    conn.commit()
    return conn

def _load_overrides() -> dict:
    """Return {app_id: {decision, label, env, ts}} for all stored overrides."""
    try:
        with _overrides_conn() as conn:
            rows = conn.execute("SELECT * FROM overrides").fetchall()
            return {r["app_id"]: dict(r) for r in rows}
    except Exception:
        return {}

def _save_override(app_id: str, decision: str | None, label: str, env: str) -> None:
    """Upsert or delete an override. decision=None clears it."""
    with _overrides_conn() as conn:
        if decision is None:
            conn.execute("DELETE FROM overrides WHERE app_id = ?", (app_id,))
        else:
            conn.execute("""
                INSERT INTO overrides (app_id, decision, label, env, ts)
                VALUES (?, ?, ?, ?, strftime('%Y-%m-%d %H:%M:%S', 'now'))
                ON CONFLICT(app_id) DO UPDATE SET
                    decision = excluded.decision,
                    label    = excluded.label,
                    env      = excluded.env,
                    ts       = excluded.ts
            """, (app_id, decision, label, env))
        conn.commit()

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, Response, stream_with_context

try:
    import keyring as _keyring
    KEYRING_SERVICE = "okta-app-admin"
except ImportError:
    _keyring = None
    KEYRING_SERVICE = ""

load_dotenv(Path(__file__).parent / ".env")

# Share okta_client.py from Okta Admin
sys.path.insert(0, str(Path(__file__).parent.parent / "Okta Admin"))
from okta_client import OKTA_ENVIRONMENTS, OktaClient

APP_VERSION = "1.1.0"

app = Flask(__name__)


def get_token(var_name: str) -> str:
    if _keyring:
        val = _keyring.get_password(KEYRING_SERVICE, var_name)
        if val:
            return val.strip()
    return os.environ.get(var_name, "").strip()


def _client(env: str):
    if env not in OKTA_ENVIRONMENTS:
        return None, (jsonify({"error": f"Unknown environment: {env}"}), 400)
    env_cfg = OKTA_ENVIRONMENTS[env]
    token = get_token(env_cfg["token_var"])
    if not token:
        return None, (jsonify({"error": f"{env_cfg['token_var']} is not set"}), 400)
    return OktaClient(env_cfg["url"], token), None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    resp = app.make_response(render_template("index.html", version=APP_VERSION))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/apps")
def api_apps():
    """Fetch all SAML apps — only fields needed for OIN migration."""
    env = request.args.get("env", "dev")
    client, err = _client(env)
    if err:
        return err
    try:
        apps = client.get_all_apps()
        result = []
        for a in apps:
            if a.get("signOnMode") != "SAML_2_0":
                continue
            if "scim" in a.get("name", "").lower():
                continue
            result.append({
                "id":           a["id"],
                "label":        a.get("label", ""),
                "name":         a.get("name", ""),
                "sign_on_mode": a.get("signOnMode", ""),
                "status":       a.get("status", ""),
            })
        result.sort(key=lambda x: x["label"].lower())
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/oin-scan")
def api_oin_scan():
    env = request.args.get("env", "dev")
    client, err = _client(env)
    if err:
        return err
    try:
        apps = client.get_all_apps()
        saml_apps = [a for a in apps if a.get("signOnMode") in ("SAML_2_0", None) and "scim" not in a.get("name", "").lower()]
        results = []
        for a in saml_apps:
            label  = a.get("label", "")
            name   = a.get("name", "")
            status = a.get("status", "")

            if not (name.startswith("senate_") or name.startswith("dev-senate_") or name.startswith("stg-senate_")):
                oin_state = "already_oin"
                matches   = []
            elif label.endswith(" [REPLACED]"):
                oin_state = "replaced"
                matches   = []
            elif label.endswith(" [LEGACY]"):
                oin_state = "legacy"
                matches   = []
            elif status != "ACTIVE":
                oin_state = "inactive"
                matches   = []
            else:
                search_term = label.removesuffix(" [REPLACED]").removesuffix(" [LEGACY]").removeprefix("[LEGACY] ")
                matches     = client.search_oin_catalog(search_term)
                oin_state   = "candidates" if matches else "no_match"

            results.append({
                "id":           a["id"],
                "label":        label,
                "name":         name,
                "sign_on_mode": a.get("signOnMode", ""),
                "status":       status,
                "oin_state":    oin_state,
                "oin_matches":  matches,
                "note":         (a.get("notes") or {}).get("admin") or "",
            })
        # Merge persisted user overrides into results
        overrides = _load_overrides()
        for r in results:
            ov = overrides.get(r["id"])
            r["user_decision"] = ov["decision"] if ov else None

        results.sort(key=lambda x: (
            {"candidates": 0, "no_match": 1, "already_oin": 2, "inactive": 3, "legacy": 4, "replaced": 5}
            .get(x["oin_state"], 9),
            x["label"].lower()
        ))
        counts = {s: sum(1 for r in results if r["oin_state"] == s)
                  for s in ("candidates", "no_match", "already_oin", "inactive", "legacy", "replaced")}
        _log_action(env, "SCAN", f"{len(results)} SAML apps", "ok",
                    f"candidates={counts['candidates']} no_match={counts['no_match']} "
                    f"already_oin={counts['already_oin']} inactive={counts['inactive']} "
                    f"legacy={counts['legacy']} replaced={counts['replaced']}")
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/convert", methods=["POST"])
def api_convert():
    """
    Full conversion pipeline for confirmed apps:
      1. Stamp legacy app as "App Name [LEGACY]"
      2. Create OIN instance
      3. Copy SAML config
      4. Copy group/user assignments
      5. Copy auth policy + routing rule
    Payload: {env, conversions: [{app_id, oin_key, label}]}
    """
    data = request.get_json()
    env       = data.get("env", "dev")
    keep_name = data.get("keep_name", True)
    conversions = data.get("conversions", [])
    if not conversions:
        return jsonify({"error": "conversions required"}), 400
    client, err = _client(env)
    if err:
        return err

    policy_map  = client.get_app_policy_map()
    routing_map = client.get_app_routing_rule_map()
    results = {}

    for conv in conversions:
        legacy_id = conv["app_id"]
        oin_key   = conv["oin_key"]
        label     = conv["label"]   # original label without [LEGACY]
        result    = {"ok": False}
        try:
            log.debug("[%s] START convert  oin_key=%s  label=%s  keep_name=%s", legacy_id, oin_key, label, keep_name)

            # Fetch legacy app once — reuse for settings + stamp
            legacy_data = client.get_app(legacy_id)
            log.debug("[%s] legacy app fetched: label=%s  settings.app=%s",
                      legacy_id, legacy_data.get("label"),
                      json.dumps(legacy_data.get("settings", {}).get("app", {})))

            # 1. Create OIN instance
            log.debug("[%s] creating OIN instance...", legacy_id)
            oin_app = client.create_oin_instance(oin_key, label, legacy_data.get("settings"))
            oin_id  = oin_app["id"]
            result["oin_id"] = oin_id
            log.debug("[%s] OIN instance created: %s", legacy_id, oin_id)

            # 1a. Rename OIN instance to original label if keep_name is set
            #     (OIN templates may override the label with their own default name)
            if keep_name and oin_app.get("label") != label:
                log.debug("[%s] renaming OIN instance '%s' → '%s'", legacy_id, oin_app.get("label"), label)
                client.rename_app(oin_id, label)

            # 2. Copy SAML config
            log.debug("[%s] copying SAML config...", legacy_id)
            saml = client.copy_saml_config(legacy_id, oin_id)
            result["saml"] = saml
            log.debug("[%s] SAML config: %s", legacy_id, saml)

            # 3. Copy assignments
            log.debug("[%s] copying assignments...", legacy_id)
            assignments = client.copy_assignments(legacy_id, oin_id)
            result["assignments"] = assignments
            log.debug("[%s] assignments: %s", legacy_id, assignments)

            # 4. Copy auth policy + routing rule
            log.debug("[%s] copying policy...", legacy_id)
            result["policy"] = client.copy_policy(legacy_id, oin_id, policy_map)
            log.debug("[%s] policy: %s", legacy_id, result["policy"])

            log.debug("[%s] copying routing rule...", legacy_id)
            result["routing_rule"] = client.copy_routing_rule(legacy_id, oin_id, routing_map)
            log.debug("[%s] routing_rule: %s", legacy_id, result["routing_rule"])

            # 5. Stamp legacy app as [REPLACED] — only after everything else succeeds
            current_label = legacy_data.get("label", "")
            already_marked = current_label.endswith(" [REPLACED]") or current_label.endswith(" [LEGACY]")
            stamped_label  = current_label if already_marked else f"{current_label} [REPLACED]"
            if not already_marked:
                log.debug("[%s] stamping: %s → %s", legacy_id, current_label, stamped_label)
                client.rename_app(legacy_id, stamped_label)
            result["stamped_label"] = stamped_label

            result["ok"] = True
            log.debug("[%s] DONE ok", legacy_id)
            _log_action(env, "CONVERT", label, "ok", f"→ {oin_key}  new_id={oin_id}")
        except Exception as e:
            import traceback as _tb
            tb_last = _tb.format_exc().strip().splitlines()
            tb_line = next((l.strip() for l in reversed(tb_last) if l.strip().startswith("File")), "")
            log.exception("[%s] FAILED: %s", legacy_id, e)
            result["error"] = str(e)
            _log_action(env, "CONVERT", label, "FAILED", f"{e} — {tb_line}")

            # If failure is an enum validation error, mark review_needed + write note
            err_str = str(e)
            try:
                err_json = json.loads(err_str[err_str.index("{"):]) if "{" in err_str else {}
            except Exception:
                err_json = {}
            enum_fields = [
                c["errorSummary"].split(":")[0].strip()
                for c in err_json.get("errorCauses", [])
                if "not one of the allowed values" in c.get("errorSummary", "").lower()
            ]
            if enum_fields:
                note = (f"Convert failed — OIN template requires manual field values: "
                        f"{', '.join(enum_fields)}. "
                        f"OIN key: {oin_key}. Set these in the OIN app after manual creation.")
                try:
                    client.set_app_note(legacy_id, note)
                except Exception:
                    pass
                _save_override(legacy_id, "review_needed", label, env)
                result["review_needed"] = True
                result["enum_fields"] = enum_fields

        results[legacy_id] = result

    return jsonify(results)


@app.route("/api/override", methods=["POST"])
def api_override():
    """Persist or clear a user decision (no_oin, review_needed) for an app."""
    data     = request.get_json()
    env      = data.get("env", "dev")
    app_id   = data.get("app_id", "").strip()
    decision = data.get("decision")  # 'no_oin' | 'review_needed' | null (clear)
    label    = data.get("label", app_id)

    if not app_id:
        return jsonify({"error": "app_id required"}), 400
    if decision not in (None, "no_oin", "review_needed"):
        return jsonify({"error": "decision must be no_oin, review_needed, or null"}), 400

    try:
        _save_override(app_id, decision, label, env)
        action = "cleared" if decision is None else decision
        _log_action(env, "OVERRIDE", label, action)
        return jsonify({"ok": True, "app_id": app_id, "decision": decision})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/note", methods=["POST"])
def api_note():
    data = request.get_json()
    env = data.get("env", "dev")
    app_id = data.get("app_id", "").strip()
    note = data.get("note", "")
    if not app_id:
        return jsonify({"error": "app_id required"}), 400
    client, err = _client(env)
    if err:
        return err
    try:
        app_data = client.get_app(app_id)
        label = app_data.get("label", app_id)
        client.set_app_note(app_id, note)
        _log_action(env, "NOTE", label, "ok", f'"{note[:60]}"' if note else "(cleared)")
        return jsonify({"ok": True, "note": note})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/stamp-legacy", methods=["POST"])
def api_stamp_legacy():
    data = request.get_json()
    env = data.get("env", "dev")
    app_ids = data.get("app_ids", [])
    if not app_ids:
        return jsonify({"error": "app_ids required"}), 400
    client, err = _client(env)
    if err:
        return err
    results = {}
    for aid in app_ids:
        try:
            app_data = client.get_app(aid)
            current_label = app_data.get("label", "")
            already = (current_label.endswith(" [LEGACY]") or current_label.endswith(" [REPLACED]")
                       or current_label.startswith("[LEGACY] "))
            if already:
                results[aid] = {"ok": True, "new_label": current_label, "skipped": True}
                _log_action(env, "STAMP", current_label, "skipped", "already stamped")
            else:
                new_label = f"{current_label} [LEGACY]"
                client.rename_app(aid, new_label)
                results[aid] = {"ok": True, "new_label": new_label}
                _log_action(env, "STAMP", current_label, "ok", f"→ {new_label}")
        except Exception as e:
            results[aid] = {"ok": False, "error": str(e)}
            _log_action(env, "STAMP", aid, "FAILED", str(e))
    return jsonify(results)


# ---------------------------------------------------------------------------
# AI Review — claude CLI subprocess, streams NDJSON
# ---------------------------------------------------------------------------

_OIN_REVIEW_PROMPT_PREFIX = """You are reviewing Okta Integration Network (OIN) app matches for the US Senate — a US federal government organization migrating pre-staged custom SAML apps to proper OIN templates.

Context:
- Custom SAML apps were staged by an ADFS-to-Okta migration tool. We want to replace them with OIN templates where one exists.
- For government orgs, prefer Gov/Federal OIN variants (e.g. "Zoom for Government" over plain "Zoom").
- Prefer verified OIN apps over unverified. Prefer exact name matches over partial.

CRITICAL RULES — no exceptions:
- oin_name MUST be the exact key= value from the CANDIDATES list provided for that app.
- If an app has no CANDIDATES listed, you MUST return decision=no_oin or decision=review_needed and oin_name=null.
- NEVER invent, guess, or derive an OIN key. The catalog is the only source of truth.
- If CANDIDATES exist but none are a clear match, return review_needed with oin_name=null.

For each app return one of these decisions:
  confirmed     - clear correct OIN match from CANDIDATES, high confidence
  suggested     - probable match from CANDIDATES, may need quick verification
  review_needed - multiple valid CANDIDATES exist, or no confident match, human must pick
  no_oin        - no OIN equivalent exists (Senate-specific, proprietary, on-prem, or niche) AND no CANDIDATES listed

Known Senate-specific apps with no OIN equivalent: IPTV, ComputerWorks-InterTrac, Democratic Cloakroom, JEMNS, GRB, WebEOC, SLC leg server, MATT-Openshift, CE Services, DataPointer, SOAP, SnapStream, PageFlex, SAAOnCall, iConstituent (custom instance), Senate Library.

Apps to review:
"""

_OIN_REVIEW_PROMPT_SUFFIX = """

Respond with ONLY a JSON object in this exact format, no markdown:
{"reviews": [{"app_id": "...", "decision": "confirmed|suggested|review_needed|no_oin", "oin_name": "exact_key_from_candidates_or_null", "oin_display": "Display Name or null", "reason": "one sentence"}]}"""


def _build_app_line(a: dict) -> str:
    line = f"APP_ID={a['id']} | LABEL={a['label']} | STATE={a['oin_state']}"
    if a.get("oin_matches"):
        cands = "; ".join(
            f"{m['displayName']} (key={m['name']}, verified={m['verified']}, exact={m['exact']}, gov={m.get('gov', False)})"
            for m in a["oin_matches"]
        )
        line += f" | CANDIDATES={cands}"
    return line


_CLAUDE_TIMEOUT = 120  # seconds per batch before killing the subprocess

# Env vars the claude subprocess actually needs — explicitly whitelist to avoid
# leaking Okta API tokens into the child process environment.
_CLAUDE_ENV_ALLOWLIST = {"PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL",
                         "TMPDIR", "TMP", "TEMP", "XDG_RUNTIME_DIR",
                         "CLAUDE_CONFIG_DIR", "NODE_EXTRA_CA_CERTS",
                         "NODE_TLS_REJECT_UNAUTHORIZED"}


def _run_claude_batch(claude_bin: str, env: dict, batch: list[dict], model: str | None = None) -> list[dict]:
    import subprocess as _sp
    import json as _json

    safe_env = {k: v for k, v in env.items() if k in _CLAUDE_ENV_ALLOWLIST}

    prompt = _OIN_REVIEW_PROMPT_PREFIX + "\n".join(_build_app_line(a) for a in batch) + _OIN_REVIEW_PROMPT_SUFFIX
    cmd = [
        claude_bin, "-p", prompt,
        "--output-format", "stream-json",
        "--verbose",
        "--include-partial-messages",
        "--permission-mode", "bypassPermissions",
        "--no-session-persistence",
    ]
    if model:
        cmd += ["--model", model]
    proc = _sp.Popen(
        cmd,
        stdout=_sp.PIPE,
        stderr=_sp.PIPE,
        text=True,
        env=safe_env,
        start_new_session=True,
    )
    full_text = []
    try:
        for raw in proc.stdout:
            raw = raw.strip()
            if not raw:
                continue
            try:
                event = _json.loads(raw)
            except _json.JSONDecodeError:
                continue
            if event.get("type") == "stream_event":
                ev = event.get("event", {})
                if ev.get("type") == "content_block_delta":
                    delta = ev.get("delta", {})
                    if delta.get("type") == "text_delta":
                        full_text.append(delta.get("text", ""))
            elif event.get("type") == "result" and event.get("is_error"):
                raise RuntimeError(event.get("result", "claude CLI error"))
        try:
            proc.wait(timeout=_CLAUDE_TIMEOUT)
        except _sp.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise RuntimeError(f"claude timed out after {_CLAUDE_TIMEOUT}s")
    except Exception:
        # Ensure process is cleaned up on any exception
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        raise

    text = "".join(full_text).strip()
    if not text:
        stderr = proc.stderr.read().strip()
        raise RuntimeError(f"claude returned no output. stderr: {stderr or '(empty)'}")

    # Strip markdown fences if present — only remove first and last lines
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop opening fence (first line) and closing fence (last line if it's ```)
        start = 1
        end = len(lines) - 1 if lines[-1].strip().startswith("```") else len(lines)
        text = "\n".join(lines[start:end]).strip()

    try:
        return _json.loads(text).get("reviews", [])
    except _json.JSONDecodeError as e:
        raise RuntimeError(f"JSON parse error: {e}. Raw text: {text[:300]}")


_review_cancel_tokens: set[str] = set()


@app.route("/api/oin-ai-review/cancel", methods=["POST"])
def api_oin_ai_review_cancel():
    token = request.get_json(silent=True, force=True) or {}
    tid = token.get("review_id")
    if tid:
        _review_cancel_tokens.add(tid)
    return jsonify({"ok": True})


@app.route("/api/oin-ai-review", methods=["POST"])
def api_oin_ai_review():
    import json as _json
    import glob as _glob
    import uuid as _uuid

    data = request.get_json()
    apps = data.get("apps", [])

    review_apps = [a for a in apps if a.get("oin_state") in ("candidates", "no_match")]
    if not review_apps:
        return jsonify({"reviews": []})

    model = data.get("model") or None
    req_env = data.get("env", "dev")

    # Enrich no_match apps with live catalog results — catalog is source of truth,
    # Claude must only pick from returned candidates, never guess a key.
    client, client_err = _client(req_env)
    if not client_err:
        for a in review_apps:
            if a.get("oin_state") == "no_match" and not a.get("oin_matches"):
                try:
                    a["oin_matches"] = client.search_oin_catalog(a["label"])
                except Exception:
                    a["oin_matches"] = []

    env = {k: v for k, v in os.environ.items()}
    cc = sorted(_glob.glob(os.path.expanduser("~/.vscode/extensions/anthropic.claude-code-*/resources/native-binary/claude")))
    claude_bin = cc[-1] if cc else "claude"

    BATCH_SIZE = 20
    batches = [review_apps[i:i + BATCH_SIZE] for i in range(0, len(review_apps), BATCH_SIZE)]

    review_id = _uuid.uuid4().hex

    def generate():
        yield _json.dumps({"type": "start", "review_id": review_id}) + "\n"
        try:
            for i, batch in enumerate(batches, 1):
                if review_id in _review_cancel_tokens:
                    _review_cancel_tokens.discard(review_id)
                    yield _json.dumps({"type": "cancelled"}) + "\n"
                    return
                labels = ", ".join(a["label"] for a in batch[:3])
                if len(batch) > 3:
                    labels += f" +{len(batch) - 3} more"
                apps_in_batch = [a["label"] for a in batch]
                yield _json.dumps({
                    "type": "progress",
                    "batch": i,
                    "total": len(batches),
                    "count": len(batch),
                    "label": labels,
                    "apps": apps_in_batch,
                }) + "\n"
                try:
                    reviews = _run_claude_batch(claude_bin, env, batch, model=model)
                    yield _json.dumps({"type": "reviews", "reviews": reviews}) + "\n"
                    for r in reviews:
                        _log_action(
                            data.get("env", "dev"), "AI_REVIEW",
                            next((a["label"] for a in batch if a.get("id") == r.get("app_id")), r.get("app_id", "")),
                            r.get("decision", ""),
                            f"{r.get('oin_display') or r.get('oin_name') or ''} — {r.get('reason', '')}".strip(" —")
                        )
                except Exception as e:
                    yield _json.dumps({"type": "batch_error", "batch": i, "message": str(e)}) + "\n"
        finally:
            _review_cancel_tokens.discard(review_id)
        yield _json.dumps({"type": "done"}) + "\n"

    return Response(stream_with_context(generate()), mimetype="application/x-ndjson")


# ---------------------------------------------------------------------------
# SP Config — Claude-generated vendor instructions (ZIP download)
# ---------------------------------------------------------------------------

def _find_claude() -> str:
    candidates = sorted(glob.glob(
        os.path.expanduser("~/.vscode/extensions/anthropic.claude-code-*/resources/native-binary/claude")
    ))
    return candidates[-1] if candidates else "claude"


def _safe_filename(label: str) -> str:
    slug = _re.sub(r'[^\w\s-]', '', label).strip()
    slug = _re.sub(r'[\s]+', '-', slug)
    return slug[:60] or "app"


def _call_claude(prompt: str) -> str:
    """Call Claude CLI for text generation; returns full response text."""
    safe_env = {k: v for k, v in os.environ.items() if k in _CLAUDE_ENV_ALLOWLIST}
    claude = _find_claude()
    proc = subprocess.Popen(
        [claude, "-p", prompt,
         "--output-format", "stream-json",
         "--verbose",
         "--include-partial-messages",
         "--permission-mode", "bypassPermissions",
         "--no-session-persistence"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=safe_env, start_new_session=True,
    )
    chunks = []
    try:
        for raw in proc.stdout:
            raw = raw.strip()
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "stream_event":
                ev = event.get("event", {})
                if ev.get("type") == "content_block_delta":
                    delta = ev.get("delta", {})
                    if delta.get("type") == "text_delta":
                        chunks.append(delta.get("text", ""))
            elif event.get("type") == "result" and event.get("is_error"):
                raise RuntimeError(event.get("result", "claude error"))
        try:
            proc.wait(timeout=_CLAUDE_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
            raise RuntimeError(f"Claude timed out after {_CLAUDE_TIMEOUT}s")
    except Exception:
        if proc.poll() is None:
            proc.kill(); proc.wait()
        raise
    return "".join(chunks).strip()


_SP_CONFIG_PROMPT = """\
You are an Okta SSO administrator preparing SP (Service Provider) configuration instructions for a vendor or SP administrator.

Write plain configuration instructions — no greeting, no closing, no email framing. Just the instructions.

The configuration values are already extracted and provided below. Present them clearly and write a "What to do" section tailored to this specific application.

Rules:
- Lead with the Metadata URL
- Present all provided values with clear labels
- No markdown, no bullet symbols — plain text with line breaks
- No sign-off, no signature

If is_oin=true:
  Add this note after the Metadata URL: "Note: Most modern SAML service providers can auto-configure from the metadata URL alone. The values below are provided for reference or for vendors that require manual entry."
  Write a "What to do" section with 3-5 steps focused on importing the metadata URL.

If is_oin=false:
  This is a custom (non-OIN) SAML application. The SP admin's platform may not support automatic metadata import. Write a "What to do" section that covers all three common configuration paths and tells the admin to use whichever their platform supports:
  1. Metadata URL import (if their platform supports it — paste the URL and let it auto-populate)
  2. Raw metadata XML upload (download from the metadata URL and upload the XML file)
  3. Manual entry (copy IDP SSO URL, IDP Entity ID, and download the signing certificate PEM for upload)
  Keep the steps practical and platform-agnostic — do not assume any specific vendor portal layout.

App configuration:
{details}
"""


def _build_sp_details(cfg: dict, env: str) -> str:
    attr_lines = ""
    if cfg.get("attr_stmts"):
        attr_lines = "\nAttribute Statements:\n" + "\n".join(
            f"  {a.get('name','')}: {a.get('values', a.get('value',''))}"
            for a in cfg["attr_stmts"]
        )
    return (
        f"App Name: {cfg['label']}\n"
        f"Environment: {env.upper()}\n"
        f"OIN App (is_oin): {'true' if cfg.get('is_oin') else 'false'}\n"
        f"\nMetadata URL: {cfg['metadata_url']}\n"
        f"\nIDP SSO URL: {cfg.get('idp_sso_url') or ''}\n"
        f"IDP Entity ID: {cfg.get('idp_entity_id') or ''}\n"
        f"Signing Certificate (PEM):\n{cfg.get('cert_pem') or ''}\n"
        f"\nACS URL (Reply URL): {cfg.get('acs_url') or ''}\n"
        f"Entity ID / Audience URI: {cfg.get('entity_id') or ''}\n"
        f"NameID Format: {cfg.get('nameid_format') or ''}"
        f"{attr_lines}"
    )


@app.route("/api/sp-config-stream", methods=["POST"])
def api_sp_config_stream():
    """Stream SP config generation — one NDJSON event per app, client assembles ZIP."""
    data    = request.get_json()
    env     = data.get("env", "dev")
    app_ids = data.get("app_ids", [])
    if not app_ids:
        return jsonify({"error": "app_ids required"}), 400

    client, err = _client(env)
    if err:
        return err

    def generate():
        success = 0
        for app_id in app_ids:
            try:
                cfg  = client.get_saml_config(app_id)
                label = cfg['label']
                slug  = _safe_filename(label)
                if cfg.get("status") != "ACTIVE":
                    _log_action(env, "SP_CONFIG", label, "skipped", "inactive")
                    yield json.dumps({"type": "skip", "label": label, "reason": "inactive"}) + "\n"
                    continue
                yield json.dumps({"type": "start", "label": label}) + "\n"
                details = _build_sp_details(cfg, env)
                prompt  = _SP_CONFIG_PROMPT.format(details=details)
                text    = _call_claude(prompt)
                _log_action(env, "SP_CONFIG", label, "ok")
                success += 1
                yield json.dumps({"type": "result", "label": label,
                                  "filename": f"{slug}-sp-config.txt", "text": text}) + "\n"
            except Exception as e:
                label = cfg['label'] if 'cfg' in dir() else app_id
                _log_action(env, "SP_CONFIG", label, "FAILED", str(e))
                log.warning("sp-config failed for %s: %s", app_id, e)
                yield json.dumps({"type": "error", "label": label, "message": str(e)}) + "\n"
        yield json.dumps({"type": "done", "success": success, "total": len(app_ids)}) + "\n"

    return Response(stream_with_context(generate()), mimetype="application/x-ndjson")


@app.route("/api/deactivate", methods=["POST"])
def api_deactivate():
    """Deactivate apps without deleting."""
    data    = request.get_json()
    env     = data.get("env", "dev")
    app_ids = data.get("app_ids", [])
    if not app_ids:
        return jsonify({"error": "app_ids required"}), 400
    client, err = _client(env)
    if err:
        return err
    results = {}
    for aid in app_ids:
        try:
            app_data = client.get_app(aid)
            label    = app_data.get("label", aid)
            client.deactivate_app(aid)
            _log_action(env, "DEACTIVATE", label, "ok")
            results[aid] = {"ok": True, "label": label}
        except Exception as e:
            _log_action(env, "DEACTIVATE", aid, "FAILED", str(e))
            results[aid] = {"ok": False, "error": str(e)}
    return jsonify(results)


@app.route("/api/purge", methods=["POST"])
def api_purge():
    """Backup config, deactivate, and delete replaced apps."""
    data    = request.get_json()
    env     = data.get("env", "dev")
    app_ids = data.get("app_ids", [])
    if not app_ids:
        return jsonify({"error": "app_ids required"}), 400
    client, err = _client(env)
    if err:
        return err
    results = {}
    for aid in app_ids:
        try:
            app_data = client.get_app(aid)
            label    = app_data.get("label", aid)
            sso      = (app_data.get("settings") or {}).get("signOn") or {}
            dump = (
                f"id={aid} signOnMode={app_data.get('signOnMode')} "
                f"acs={sso.get('ssoAcsUrl') or sso.get('ssoAcsUrlOverride', '')} "
                f"audience={sso.get('audience') or sso.get('audienceOverride', '')}"
            )
            _log_action(env, "PURGE", label, "backup", dump)
            client.deactivate_app(aid)
            client.delete_app(aid)
            _log_action(env, "PURGE", label, "ok", "deactivated + deleted")
            results[aid] = {"ok": True, "label": label}
        except Exception as e:
            _log_action(env, "PURGE", aid, "FAILED", str(e))
            results[aid] = {"ok": False, "error": str(e)}
    return jsonify(results)


# ── Logs page ────────────────────────────────────────────────────────────────

@app.route("/logs")
def logs_page():
    log_file = Path(__file__).parent / "oin-actions.log"
    lines = []
    if log_file.exists():
        with open(log_file, encoding="utf-8") as f:
            lines = f.readlines()
    return render_template("logs.html", lines=lines[-500:])  # last 500 entries


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5003))
    print(f"\n  OIN Migration Tool v{APP_VERSION}")
    print(f"  Open: http://localhost:{port}\n")
    app.run(host="127.0.0.1", port=port, debug=True, use_reloader=True, threaded=True)
