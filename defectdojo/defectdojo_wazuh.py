#!/usr/bin/env python3
"""
Usage:
    python3 defectdojo_wazuh.py --mode all --product-ids 12,47,88
    python3 defectdojo_wazuh.py --mode critical_high --products "Payments API,Customer Portal,Auth Service"

Environment variables (can also be passed as CLI flags, flags win):
    DEFECTDOJO_URL        e.g. https://defectdojo.example.com
    DEFECTDOJO_API_KEY    DefectDojo API v2 token
    DD_WAZUH_MODE         "all" or "critical_high"
    DD_WAZUH_PRODUCT_IDS  Comma-separated DefectDojo product IDs to include (recommended -- exact, no lookup needed)
    DD_WAZUH_PRODUCTS     Comma-separated exact DefectDojo product NAMES to include (resolved to IDs at startup)
    DD_WAZUH_QUEUE_SOCKET Path to Wazuh queue socket (default /var/ossec/queue/sockets/queue)
    DD_WAZUH_LOG_FALLBACK Path to fallback log file (default /var/ossec/logs/defectdojo/findings.log)
    DD_WAZUH_STATE_FILE   Path to state file tracking last-seen findings
    DD_WAZUH_PAGE_SIZE    DefectDojo API page size (default 100)
    DD_WAZUH_VERIFY_TLS   "true"/"false" (default true)
    DD_WAZUH_REALERT_DAYS Days to suppress repeat alerts for the same vulnerability fingerprint (default 7, 0 disables dedup)

"""

import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.stderr.write(
        "ERROR: the 'requests' library is required. Install with:\n"
        "  pip3 install requests --break-system-packages\n"
    )
    sys.exit(1)

# --------------------------------------------------------------------------
# Severity -> Wazuh rule level mapping (1:1 mode)
# --------------------------------------------------------------------------
# These map to the custom rules defined in defectdojo_rules.xml. Keep the
# two files in sync if you change levels here.
SEVERITY_LEVEL_MAP = {
    "Critical": 15,
    "High": 12,
    "Medium": 7,
    "Low": 4,
    "Info": 2,
}

# Findings with these severities are forwarded in "critical_high" mode.
CRITICAL_HIGH_SEVERITIES = {"Critical", "High"}

DEFAULT_QUEUE_SOCKET = "/var/ossec/queue/sockets/queue"
DEFAULT_LOG_FALLBACK = "/var/ossec/logs/defectdojo/findings.log"
DEFAULT_STATE_FILE = "/var/ossec/etc/defectdojo_wazuh_state.json"
DEFAULT_PAGE_SIZE = 100
DEFAULT_REALERT_DAYS = 7

# Wazuh wire format prefix: a 1-byte queue location code identifying the
# log source. "1" is traditionally used for syslog-type custom messages.
QUEUE_LOCATION_CODE = "1"


def env_bool(name, default=True):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def load_state(state_file):
    """
    Load persisted state. Schema:
      last_id_seen: highest DefectDojo finding id fetched so far (used to
          scope the API query, NOT to decide what gets forwarded -- that
          decision is made per-fingerprint, see fingerprint_last_sent).
      fingerprint_last_sent: {fingerprint: ISO8601 timestamp} of the last
          time a given vulnerability fingerprint (see compute_fingerprint())
          was actually forwarded to Wazuh. Used to suppress re-alerting the
          same vulnerability across reimports that assign it a new finding
          id, while still re-alerting after DD_WAZUH_REALERT_DAYS if it's
          still active.

    Older state files (pre-dedup) only have last_id_seen/sent_finding_ids;
    fingerprint_last_sent defaults to {} for those so the first run after
    upgrading just starts populating it fresh (no findings are lost or
    double-suppressed by this migration).
    """
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                state = json.load(f)
                state.setdefault("last_id_seen", 0)
                state.setdefault("fingerprint_last_sent", {})
                return state
        except (json.JSONDecodeError, OSError):
            sys.stderr.write(f"WARNING: could not read state file {state_file}, starting fresh\n")
    return {"last_id_seen": 0, "fingerprint_last_sent": {}}


def save_state(state_file, state):
    tmp_path = state_file + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(state, f)
    os.replace(tmp_path, state_file)


def compute_fingerprint(finding, product_id):
    """
    Build a stable identifier for "the same vulnerability" that survives
    DefectDojo assigning a brand-new finding id on every reimport (a
    documented DefectDojo behavior when Reimport Deduplication isn't
    tuned to the scan type, or when scans always create a new Test).

    Preferred key: CVE + component name + component version + product id
    -- this is what actually identifies "this CVE in this dependency in
    this product" regardless of which finding id DefectDojo assigns it.
    Falls back to title + product id when no CVE is present (e.g. SAST
    findings without an assigned CVE), which is less precise but still
    far better than relying on the ever-changing finding id alone.
    """
    cve = finding.get("cve")
    if not cve:
        vuln_ids = finding.get("vulnerability_ids") or []
        if vuln_ids and isinstance(vuln_ids[0], dict):
            cve = vuln_ids[0].get("vulnerability_id")
        elif vuln_ids and isinstance(vuln_ids[0], str):
            cve = vuln_ids[0]

    component = finding.get("component_name") or ""
    version = finding.get("component_version") or ""

    if cve:
        return f"cve:{cve}|component:{component}|version:{version}|product:{product_id}"

    title = finding.get("title") or ""
    return f"title:{title}|product:{product_id}"


def resolve_product_names_to_ids(base_url, api_key, verify_tls, product_names):
    """
    Look up DefectDojo product IDs for a list of exact product names.
    Raises if a name doesn't resolve to exactly one product, so a typo'd
    product name fails loudly at startup instead of silently forwarding
    zero (or the wrong) findings.
    """
    url = f"{base_url.rstrip('/')}/api/v2/products/"
    headers = {"Authorization": f"Token {api_key}"}
    resolved_ids = []
    for name in product_names:
        resp = requests.get(url, headers=headers, params={"name": name, "limit": 50},
                             verify=verify_tls, timeout=30)
        resp.raise_for_status()
        results = resp.json().get("results", [])
        exact = [p for p in results if p.get("name") == name]
        if not exact:
            raise ValueError(f"No DefectDojo product found with exact name '{name}'")
        if len(exact) > 1:
            raise ValueError(f"Multiple DefectDojo products named '{name}' -- use --product-ids instead")
        resolved_ids.append(exact[0]["id"])
    return resolved_ids


def fetch_product_names(base_url, api_key, verify_tls, product_ids):
    """
    Look up display names for a list of product IDs, one request per ID
    (the /api/v2/products/{id}/ detail endpoint is used rather than the
    list endpoint so a single malformed/deleted ID can't silently break
    the whole batch). Used only to populate the human-readable dd_product
    field on forwarded events -- dd_product_id is always correct even if
    a name lookup fails, so failures here are logged and tolerated rather
    than fatal.
    """
    headers = {"Authorization": f"Token {api_key}"}
    names = {}
    for pid in product_ids:
        url = f"{base_url.rstrip('/')}/api/v2/products/{pid}/"
        try:
            resp = requests.get(url, headers=headers, verify=verify_tls, timeout=30)
            resp.raise_for_status()
            names[pid] = resp.json().get("name", f"product-{pid}")
        except requests.exceptions.RequestException as e:
            sys.stderr.write(f"WARNING: could not resolve name for product_id={pid}: {e}\n")
            names[pid] = f"product-{pid}"
    return names


def fetch_findings(base_url, api_key, page_size, verify_tls, since_id=None, product_ids=None):
    """
    Fetch active findings from DefectDojo, ordered by id ascending, paging
    through results. Uses the 'active=true' filter so closed/mitigated
    findings are not re-alerted. Adjust the filter if you also want to
    alert on risk-accepted or false-positive-marked findings differently.

    When product_ids is given (non-empty), one request per product ID is
    issued using DefectDojo's 'test__engagement__product' query filter, so
    findings for excluded products are never fetched in the first place --
    this keeps the call cheap even on instances with 200+ products. When
    product_ids is None/empty, every product is fetched (unscoped),
    matching the behavior before product filtering existed.

    Note: findings are not directly linked to products in DefectDojo's
    data model -- the relationship is finding -> test -> engagement ->
    product. There is no reliable bare 'product' filter on this endpoint
    across DefectDojo versions (some expose it as a convenience alias,
    many silently ignore it and return unfiltered results instead of
    erroring, which is what happened here). 'test__engagement__product'
    follows the actual relationship chain and is the documented/stable
    way to filter findings by product. If you hit a DefectDojo version
    where even this field 404s/400s, check /api/v2/doc/ on your instance
    for the exact field name it expects.
    """
    url = f"{base_url.rstrip('/')}/api/v2/findings/"
    headers = {"Authorization": f"Token {api_key}"}
    base_params = {
        "active": "true",
        "limit": page_size,
        "offset": 0,
        "o": "id",  # order by id ascending so pagination is stable
    }
    if since_id:
        base_params["id__gt"] = since_id

    product_id_batches = [[pid] for pid in product_ids] if product_ids else [None]

    findings = []
    for batch in product_id_batches:
        params = dict(base_params)
        params["offset"] = 0
        product_id = batch[0] if batch else None
        if product_id is not None:
            params["test__engagement__product"] = product_id

        batch_count = 0
        while True:
            resp = requests.get(url, headers=headers, params=params, verify=verify_tls, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
            # Findings have no flat 'product'/'product_id' field in
            # DefectDojo's default API response (the relationship is
            # finding -> test -> engagement -> product, and the API only
            # expands that chain if you ask for related_fields/prefetch).
            # Since we already know which product this query was scoped
            # to, stamp it on each finding now rather than trying to
            # reverse-engineer it later from a field that may not exist.
            if product_id is not None:
                for r in results:
                    r["_dd_queried_product_id"] = product_id
            findings.extend(results)
            batch_count += len(results)

            # Early sanity check: if a scoped query's FIRST page alone
            # already exceeds a sane per-product finding count, the
            # filter is probably being ignored server-side (as happened
            # when the wrong field name was used). Surface this loudly
            # instead of silently paging through the whole table again.
            total_reported = data.get("count")
            if product_id is not None and total_reported is not None and total_reported > 5000:
                sys.stderr.write(
                    f"WARNING: query scoped to product_id={product_id} reports "
                    f"{total_reported} total findings -- this looks unscoped. "
                    f"Verify 'test__engagement__product' is a valid filter field "
                    f"on this DefectDojo instance (check /api/v2/doc/).\n"
                )

            if not data.get("next"):
                break
            params["offset"] += page_size

        if product_id is not None:
            print(f"product_id={product_id}: fetched {batch_count} active finding(s)")
    return findings


def _finding_product_id(finding):
    """
    Best-effort extraction of the numeric product id a finding belongs to.

    DefectDojo's default finding response does NOT include a flat
    product/product_id field -- findings have no direct product column;
    the relationship is finding -> test -> engagement -> product, and the
    API only expands that chain if you pass related_fields=true or a
    prefetch= param, neither of which this script requests (keeping
    requests cheap). So in the normal case, the only reliable signal is
    '_dd_queried_product_id', which fetch_findings() stamps onto each
    finding based on which product-scoped query actually returned it --
    we check that first.

    The remaining checks are a fallback for DefectDojo deployments/API
    versions that DO return product info inline (e.g. if related_fields
    is added later, or other custom serializers), or for the unscoped
    (--product-ids omitted) code path where no query-time product is
    known. Return None if nothing usable is found (caller treats None as
    "does not match any allowed product").
    """
    if isinstance(finding.get("_dd_queried_product_id"), int):
        return finding["_dd_queried_product_id"]

    product = finding.get("product")
    if isinstance(product, int):
        return product
    if isinstance(product, dict) and "id" in product:
        return product["id"]

    if isinstance(finding.get("product_id"), int):
        return finding["product_id"]

    test = finding.get("test")
    if isinstance(test, dict):
        engagement = test.get("engagement")
        if isinstance(engagement, dict):
            nested_product = engagement.get("product")
            if isinstance(nested_product, int):
                return nested_product
            if isinstance(nested_product, dict) and "id" in nested_product:
                return nested_product["id"]

    return None


def build_event(finding, base_url, product_names=None):
    """
    Normalize a DefectDojo finding into the flat JSON event shape consumed
    by the Wazuh decoder (see defectdojo_decoder.xml). Field names are
    intentionally snake_case and flat to keep the decoder regex simple.

    product_names is an optional {product_id: name} map (see
    fetch_product_names()). DefectDojo's default finding response does not
    include a flat 'product_name' field, so without this map dd_product
    would come through empty -- we resolve it via the finding's product id
    instead (from _finding_product_id(), which itself prefers the
    '_dd_queried_product_id' stamped by fetch_findings()).
    """
    severity = finding.get("severity", "Info")
    engagement = finding.get("engagement_name") or finding.get("engagement") or ""
    product_id = _finding_product_id(finding)
    product = (
        finding.get("product_name")
        or (product_names or {}).get(product_id)
        or (product_id if product_id is not None else "")
    )

    event = {
        "integration": "defectdojo",
        "dd_finding_id": finding.get("id"),
        "dd_title": finding.get("title", ""),
        "dd_severity": severity,
        "dd_cwe": finding.get("cwe"),
        "dd_cve": finding.get("cve") or (finding.get("vulnerability_ids") or [None])[0],
        "dd_product": product,
        "dd_product_id": product_id,
        "dd_engagement": engagement,
        "dd_component_name": finding.get("component_name"),
        "dd_component_version": finding.get("component_version"),
        "dd_file_path": finding.get("file_path"),
        "dd_active": finding.get("active"),
        "dd_verified": finding.get("verified"),
        "dd_risk_accepted": finding.get("risk_accepted"),
        "dd_date": finding.get("date"),
        "dd_url": f"{base_url.rstrip('/')}/finding/{finding.get('id')}",
        "dd_wazuh_level": SEVERITY_LEVEL_MAP.get(severity, 2),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
    }
    return event


def send_to_wazuh(event, queue_socket, log_fallback):
    """
    Try to write the event directly to the Wazuh analysisd queue socket.
    If that fails (socket missing / permission / not on a manager), fall
    back to appending a JSON line to a log file that can be ingested via
    a <localfile> stanza instead.
    """
    payload = json.dumps(event, default=str)
    wire_message = f"{QUEUE_LOCATION_CODE}:defectdojo:{payload}"

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(queue_socket)
            s.send(wire_message.encode("utf-8"))
        return "socket"
    except (FileNotFoundError, ConnectionRefusedError, PermissionError, OSError) as e:
        os.makedirs(os.path.dirname(log_fallback), exist_ok=True)
        with open(log_fallback, "a") as f:
            f.write(payload + "\n")
        return f"log_fallback ({e})"


def main():
    parser = argparse.ArgumentParser(description="Forward DefectDojo findings into Wazuh as alerts.")
    parser.add_argument("--mode", choices=["all", "critical_high"],
                         default=os.environ.get("DD_WAZUH_MODE", "all"),
                         help="Forward all findings (1:1 severity mapping) or only critical/high findings.")
    parser.add_argument("--url", default=os.environ.get("DEFECTDOJO_URL"),
                         help="DefectDojo base URL, e.g. https://defectdojo.example.com")
    parser.add_argument("--api-key", default=os.environ.get("DEFECTDOJO_API_KEY"),
                         help="DefectDojo API v2 token")
    parser.add_argument("--product-ids", default=os.environ.get("DD_WAZUH_PRODUCT_IDS", ""),
                         help="Comma-separated DefectDojo product IDs to include. If omitted (and --products "
                              "is also omitted), ALL products are forwarded.")
    parser.add_argument("--products", default=os.environ.get("DD_WAZUH_PRODUCTS", ""),
                         help="Comma-separated exact DefectDojo product names to include (resolved to IDs at "
                              "startup). Prefer --product-ids where possible.")
    parser.add_argument("--queue-socket", default=os.environ.get("DD_WAZUH_QUEUE_SOCKET", DEFAULT_QUEUE_SOCKET))
    parser.add_argument("--log-fallback", default=os.environ.get("DD_WAZUH_LOG_FALLBACK", DEFAULT_LOG_FALLBACK))
    parser.add_argument("--state-file", default=os.environ.get("DD_WAZUH_STATE_FILE", DEFAULT_STATE_FILE))
    parser.add_argument("--page-size", type=int, default=int(os.environ.get("DD_WAZUH_PAGE_SIZE", DEFAULT_PAGE_SIZE)))
    parser.add_argument("--realert-days", type=float,
                         default=float(os.environ.get("DD_WAZUH_REALERT_DAYS", DEFAULT_REALERT_DAYS)),
                         help="Suppress repeat alerts for the same vulnerability fingerprint (CVE+component+"
                              "product) for this many days, even if DefectDojo assigns it a new finding id on "
                              "reimport. Set to 0 to disable fingerprint dedup entirely. Default: 7.")
    parser.add_argument("--dry-run", action="store_true", help="Print events instead of sending them.")
    args = parser.parse_args()

    if not args.url or not args.api_key:
        sys.stderr.write("ERROR: DEFECTDOJO_URL and DEFECTDOJO_API_KEY must be set (env or --url/--api-key).\n")
        sys.exit(2)

    verify_tls = env_bool("DD_WAZUH_VERIFY_TLS", True)

    product_ids = [int(p.strip()) for p in args.product_ids.split(",") if p.strip()]
    requested_product_names = [p.strip() for p in args.products.split(",") if p.strip()]

    if requested_product_names:
        try:
            product_ids += resolve_product_names_to_ids(args.url, args.api_key, verify_tls, requested_product_names)
        except (requests.exceptions.RequestException, ValueError) as e:
            sys.stderr.write(f"ERROR: failed to resolve --products to IDs: {e}\n")
            sys.exit(2)

    product_ids = sorted(set(product_ids))

    if not product_ids:
        sys.stderr.write(
            "WARNING: no --product-ids / --products filter set. Forwarding findings for ALL products "
            "in this DefectDojo instance. On large instances this will flood Wazuh -- pass "
            "--product-ids or --products to scope this down.\n"
        )

    # Resolve product id -> display name once up front (a handful of
    # cheap detail-endpoint calls, bounded by len(product_ids)) so every
    # forwarded event carries a human-readable dd_product instead of an
    # empty string. DefectDojo's finding payload has no flat product_name
    # field by default -- see build_event()'s docstring for why.
    product_id_to_name = {}
    if product_ids:
        try:
            product_id_to_name = fetch_product_names(args.url, args.api_key, verify_tls, product_ids)
        except requests.exceptions.RequestException as e:
            sys.stderr.write(f"WARNING: failed to resolve product names, dd_product will be numeric: {e}\n")

    state = load_state(args.state_file)
    since_id = state.get("last_id_seen", 0)

    try:
        findings = fetch_findings(args.url, args.api_key, args.page_size, verify_tls,
                                   since_id=since_id, product_ids=product_ids)
    except requests.exceptions.RequestException as e:
        sys.stderr.write(f"ERROR: failed to query DefectDojo API: {e}\n")
        sys.exit(1)

    # Defense-in-depth: even though fetch_findings() already scopes the API
    # query to product_ids, re-check the returned product id client-side.
    # This protects against API quirks (e.g. a finding's nested product
    # object missing/renamed) silently letting an out-of-scope finding
    # through.
    if product_ids:
        before = len(findings)
        findings = [f for f in findings if _finding_product_id(f) in product_ids]
        dropped = before - len(findings)
        if dropped:
            print(f"Client-side product filter dropped {dropped} out-of-scope finding(s).")

    if args.mode == "critical_high":
        findings = [f for f in findings if f.get("severity") in CRITICAL_HIGH_SEVERITIES]

    # Vulnerability-level dedup: suppress findings whose fingerprint (CVE +
    # component + product, see compute_fingerprint()) was already forwarded
    # within the last --realert-days days, regardless of the DefectDojo
    # finding id -- this is what actually fixes repeat daily alerts caused
    # by DefectDojo assigning a new id to the same vulnerability on every
    # reimport. Set --realert-days 0 to disable and fall back to id-only
    # dedup (the old behavior).
    now = datetime.now(timezone.utc)
    fingerprint_last_sent = state.get("fingerprint_last_sent", {})
    suppressed_count = 0
    to_send = []
    for finding in findings:
        if args.realert_days <= 0:
            to_send.append(finding)
            continue
        fp = compute_fingerprint(finding, _finding_product_id(finding))
        last_sent_str = fingerprint_last_sent.get(fp)
        if last_sent_str:
            try:
                last_sent = datetime.fromisoformat(last_sent_str)
            except ValueError:
                last_sent = None
            if last_sent is not None:
                age_days = (now - last_sent).total_seconds() / 86400
                if age_days < args.realert_days:
                    suppressed_count += 1
                    continue
        to_send.append(finding)
    if suppressed_count:
        print(f"Vulnerability-level dedup suppressed {suppressed_count} finding(s) already alerted "
              f"within the last {args.realert_days} day(s) (same CVE/component/product, different "
              f"DefectDojo finding id).")
    findings = to_send

    sent = 0
    max_id_seen = since_id
    for finding in findings:
        event = build_event(finding, args.url, product_names=product_id_to_name)
        fid = finding.get("id", 0)
        max_id_seen = max(max_id_seen, fid)

        if args.dry_run:
            print(json.dumps(event, indent=2, default=str))
            sent += 1
            continue

        result = send_to_wazuh(event, args.queue_socket, args.log_fallback)
        sent += 1
        print(f"[{datetime.now().isoformat()}] sent finding id={fid} severity={finding.get('severity')} via {result}")

        if args.realert_days > 0:
            fp = compute_fingerprint(finding, _finding_product_id(finding))
            fingerprint_last_sent[fp] = now.isoformat()

    if not args.dry_run:
        # Prune fingerprints last sent more than 4x the realert window ago
        # so the state file doesn't grow forever as vulnerabilities get
        # fixed over time -- a fingerprint that hasn't been seen in that
        # long will simply be treated as new (and re-tracked) if it ever
        # reappears, which is harmless.
        if args.realert_days > 0:
            prune_cutoff_days = args.realert_days * 4
            pruned = {}
            for fp, ts_str in fingerprint_last_sent.items():
                try:
                    ts = datetime.fromisoformat(ts_str)
                except ValueError:
                    continue
                if (now - ts).total_seconds() / 86400 <= prune_cutoff_days:
                    pruned[fp] = ts_str
            fingerprint_last_sent = pruned

        state["last_id_seen"] = max_id_seen
        state["fingerprint_last_sent"] = fingerprint_last_sent
        save_state(args.state_file, state)

    scope_desc = f"product_ids={product_ids}" if product_ids else "ALL products (unscoped)"
    print(f"Done. mode={args.mode} {scope_desc} findings_forwarded={sent} last_id_seen={max_id_seen}")


if __name__ == "__main__":
    main()
