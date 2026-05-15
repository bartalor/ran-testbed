#!/usr/bin/env python3
"""Live LTE testbed runner.

Brings up MongoDB + Open5GS 4G core + srsenb + srsue over ZMQ, runs an attach,
captures S1AP traffic on loopback, tears the stack down. Produces a pcap + meta
JSON sidecar that downstream tools (detectors, fuzzers, conformance suites)
consume by path.

Designed to run inside the project's container — Mongo and the eight Open5GS
daemons are launched as child processes (no systemd), so the whole stack is
owned by this script and dies with it.

    # inside the container:
    python3 /work/run.py capture legit_attach
    python3 /work/run.py capture legit_attach --out-dir /captures

Run as root (it needs SCTP sockets, raw pcap on lo, etc.).
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

LIVE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = LIVE_DIR / "configs"
OPEN5GS_CONFIG_DIR = CONFIG_DIR / "open5gs"
# Logs go to an in-container path so --rm cleans them up. On failure we dump
# the dying daemon's log tail to stderr (matches the `docker logs` idiom).
LOG_DIR = Path("/var/log/ran-testbed")
DEFAULT_OUT_DIR = LIVE_DIR / "captures"

SRSENB_BIN = Path("/usr/local/bin/srsenb")
SRSUE_BIN = Path("/usr/local/bin/srsue")
MONGOD_BIN = Path("/usr/bin/mongod")
OPEN5GS_BIN_DIR = Path("/usr/bin")

# Open5GS 4G core daemons, in start order: NRF first (service discovery for
# the 5G-style daemons that share infra), then HSS (subscriber DB), then the
# rest. PCRF last since policy depends on the others being up.
OPEN5GS_DAEMONS: tuple[str, ...] = (
    "nrf",
    "hss",
    "mme",
    "sgwc",
    "smf",
    "sgwu",
    "upf",
    "pcrf",
)

MME_SCTP_HOST = "127.0.0.2"
MME_SCTP_PORT = 36412
MONGO_HOST = "127.0.0.1"
MONGO_PORT = 27017
ZMQ_PORTS = (2000, 2001)

ENB_READY_REGEX = re.compile(r"eNodeB started", re.IGNORECASE)
S1_SETUP_FAIL_REGEX = re.compile(r"S1 Setup Failure", re.IGNORECASE)
UE_ATTACH_REGEX = re.compile(r"Network attach successful", re.IGNORECASE)
TCPDUMP_READY_REGEX = re.compile(r"listening on ", re.IGNORECASE)


# ---------- logging ----------

def log(msg: str, level: str = "info") -> None:
    ts = dt.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[x]"}.get(level, "[ ]")
    print(f"{ts} {prefix} {msg}", flush=True)


def die(msg: str, code: int = 1):
    log(msg, "err")
    sys.exit(code)


def _dump_log_tail(log_path: Path, lines: int = 30) -> None:
    """Print the last N lines of a daemon log to stderr.

    Used when a daemon dies during bring-up: logs are inside the container
    and will vanish with --rm, so we have to surface the failure now.
    """
    if not log_path.exists():
        return
    try:
        content = log_path.read_bytes().decode("utf-8", errors="replace")
    except OSError as e:
        log(f"could not read {log_path}: {e}", "warn")
        return
    tail = content.splitlines()[-lines:]
    sys.stderr.write(f"\n--- last {len(tail)} lines of {log_path} ---\n")
    sys.stderr.write("\n".join(tail) + "\n")
    sys.stderr.write("--- end ---\n\n")
    sys.stderr.flush()


# ---------- domain value objects ----------

@dataclass(frozen=True)
class PLMN:
    mcc: str
    mnc: str

    def __post_init__(self) -> None:
        if not (self.mcc.isdigit() and len(self.mcc) == 3):
            raise ValueError(f"invalid MCC {self.mcc!r}: must be exactly 3 digits")
        if not (self.mnc.isdigit() and len(self.mnc) in (2, 3)):
            raise ValueError(f"invalid MNC {self.mnc!r}: must be 2 or 3 digits")

    def __str__(self) -> str:
        return f"{self.mcc}/{self.mnc}"


@dataclass(frozen=True)
class IMSI:
    value: str

    def __post_init__(self) -> None:
        if not (self.value.isdigit() and len(self.value) == 15):
            raise ValueError(f"invalid IMSI {self.value!r}: must be exactly 15 digits")

    @property
    def mcc(self) -> str:
        return self.value[:3]

    def mnc_for(self, plmn: PLMN) -> str:
        return self.value[3 : 3 + len(plmn.mnc)]


@dataclass(frozen=True)
class UECreds:
    """UE identity + LTE root keys as configured in srsue's ue.conf.

    `k` is the 128-bit subscriber key; `opc` is the operator variant of OP
    (precomputed so the network doesn't need OP). Both are 32-hex-char
    (16 bytes). HSS stores the same triple — provisioning copies them across
    so the UE and HSS share a key, which is the whole point of AKA.
    """
    imsi: IMSI
    k: str
    opc: str


# ---------- config parsing ----------

_ENB_MCC_RE = re.compile(r"^\s*mcc\s*=\s*(\S+)\s*(?:#.*)?$")
_ENB_MNC_RE = re.compile(r"^\s*mnc\s*=\s*(\S+)\s*(?:#.*)?$")
_RR_TAC_RE = re.compile(r"^\s*tac\s*=\s*(\S+?);")
_UE_IMSI_RE = re.compile(r"^\s*imsi\s*=\s*(\d+)\s*(?:#.*)?$")
_UE_K_RE = re.compile(r"^\s*k\s*=\s*([0-9A-Fa-f]+)\s*(?:#.*)?$")
_UE_OPC_RE = re.compile(r"^\s*opc\s*=\s*([0-9A-Fa-f]+)\s*(?:#.*)?$")
_YAML_MCC_RE = re.compile(r"^\s*mcc:\s*(\S+)\s*$")
_YAML_MNC_RE = re.compile(r"^\s*mnc:\s*(\S+)\s*$")
_YAML_TAC_RE = re.compile(r"^\s*tac:\s*(\S+)\s*$")


def _uncommented_lines(path: Path):
    for raw in path.read_text().splitlines():
        s = raw.split("#", 1)[0]
        if s.strip():
            yield s


def parse_enb_plmn(path: Path) -> PLMN:
    mccs: list[str] = []
    mncs: list[str] = []
    for line in _uncommented_lines(path):
        if m := _ENB_MCC_RE.match(line):
            mccs.append(m.group(1))
        if m := _ENB_MNC_RE.match(line):
            mncs.append(m.group(1))
    if len(mccs) != 1 or len(mncs) != 1:
        die(f"{path}: expected exactly one active mcc= and one mnc=, got mcc={mccs}, mnc={mncs}")
    return PLMN(mcc=mccs[0], mnc=mncs[0])


def parse_rr_tac(path: Path) -> int:
    """Active `tac = N;` lines in srsenb rr.conf. Exactly one expected."""
    tacs: list[int] = []
    in_block_comment = False
    for raw in path.read_text().splitlines():
        # Strip libconfig block comments (`/* ... */`) and line comments (`//`).
        s = raw
        if in_block_comment:
            if "*/" in s:
                s = s.split("*/", 1)[1]
                in_block_comment = False
            else:
                continue
        if "/*" in s:
            before, _, rest = s.partition("/*")
            if "*/" in rest:
                s = before + rest.split("*/", 1)[1]
            else:
                s = before
                in_block_comment = True
        s = s.split("//", 1)[0]
        if m := _RR_TAC_RE.match(s):
            raw_val = m.group(1).strip().rstrip(";")
            tacs.append(int(raw_val, 0))  # 0x.. or decimal
    if len(tacs) != 1:
        die(f"{path}: expected exactly one active `tac = N;`, got {tacs}")
    return tacs[0]


def parse_mme_plmn_tac(path: Path) -> tuple[PLMN, int]:
    """Active gummei+tai PLMN/TAC in mme.yaml. Both PLMN blocks must agree."""
    plmns: list[PLMN] = []
    tacs: list[int] = []
    pending_mcc: str | None = None
    for raw in path.read_text().splitlines():
        if raw.lstrip().startswith("#"):
            continue
        if m := _YAML_MCC_RE.match(raw):
            pending_mcc = m.group(1)
            continue
        if m := _YAML_MNC_RE.match(raw):
            if pending_mcc is None:
                die(f"{path}: found mnc without preceding mcc near {raw!r}")
            plmns.append(PLMN(mcc=pending_mcc, mnc=m.group(1)))
            pending_mcc = None
        if m := _YAML_TAC_RE.match(raw):
            tacs.append(int(m.group(1), 0))
    if pending_mcc is not None:
        die(f"{path}: trailing mcc {pending_mcc!r} with no matching mnc")
    if len(plmns) < 2:
        die(f"{path}: expected at least 2 active PLMN blocks (gummei + tai), got {plmns}")
    if len(set(plmns)) != 1:
        die(f"{path}: PLMN blocks disagree: {plmns}")
    if len(tacs) != 1:
        die(f"{path}: expected exactly one active `tac:`, got {tacs}")
    return plmns[0], tacs[0]


def parse_ue_creds(path: Path) -> UECreds:
    """Parse imsi/k/opc from srsue's ue.conf. Exactly one active line of each."""
    imsis: list[str] = []
    ks: list[str] = []
    opcs: list[str] = []
    for line in _uncommented_lines(path):
        if m := _UE_IMSI_RE.match(line):
            imsis.append(m.group(1))
        if m := _UE_K_RE.match(line):
            ks.append(m.group(1))
        if m := _UE_OPC_RE.match(line):
            opcs.append(m.group(1))
    if len(imsis) != 1:
        die(f"{path}: expected exactly one active imsi=, got {imsis}")
    if len(ks) != 1:
        die(f"{path}: expected exactly one active k=, got {ks}")
    if len(opcs) != 1:
        die(f"{path}: expected exactly one active opc=, got {opcs}")
    k, opc = ks[0].lower(), opcs[0].lower()
    if len(k) != 32 or len(opc) != 32:
        die(f"{path}: k and opc must be 32 hex chars (128 bits); got k={len(k)}, opc={len(opc)}")
    return UECreds(imsi=IMSI(imsis[0]), k=k, opc=opc)


# ---------- process supervision ----------

@dataclass(frozen=True)
class ComponentSpec:
    """Recipe for one supervised child process.

    Readiness has two complementary signals (both optional, at least one
    required if you call wait_ready):
      - ready_regex: matched against stderr/stdout. Cheap; works for chatty
        daemons that print a clear "I'm up" line (srsenb, srsue, tcpdump).
      - ready_check: callable polled ~10×/s. Use for daemons whose log format
        is unstable or silent on stderr — e.g. mongod (poll `mongosh ping`).
    Whichever fires first wins.
    """
    name: str
    argv: tuple[str, ...]
    cwd: Path | None = None
    ready_regex: re.Pattern[str] | None = None
    ready_check: Callable[[], bool] | None = None
    fail_regex: re.Pattern[str] | None = None


@dataclass
class ComponentProc:
    spec: ComponentSpec
    proc: subprocess.Popen
    log_path: Path
    reader: threading.Thread
    ready_event: threading.Event = field(default_factory=threading.Event)
    fail_event: threading.Event = field(default_factory=threading.Event)

    def wait_ready(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        check = self.spec.ready_check
        while time.monotonic() < deadline:
            if self.ready_event.is_set():
                return True
            if self.fail_event.is_set():
                return False
            if self.proc.poll() is not None:
                return False
            if check is not None and check():
                self.ready_event.set()
                return True
            time.sleep(0.1)
        return False

    def stop(self, term_timeout: float = 5.0) -> None:
        """SIGTERM the process group, escalate to SIGKILL, then join the reader.

        Idempotent: safe to call after the process has already exited.
        Always joins the reader thread (with bounded timeout) so the log file
        is fully flushed and closed before this returns.
        """
        if self.proc.poll() is None:
            log(f"stop {self.spec.name} (pid={self.proc.pid}, sig=SIGTERM)")
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                try:
                    self.proc.wait(timeout=term_timeout)
                except subprocess.TimeoutExpired:
                    log(f"{self.spec.name} did not exit on SIGTERM, sending SIGKILL", "warn")
                    try:
                        os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        self.proc.wait(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        log(f"{self.spec.name} ignored SIGKILL", "err")
            except ProcessLookupError:
                pass
        # Reader exits on stdout EOF; bounded join so the interpreter can't yank
        # a daemon thread mid-write and truncate the log.
        self.reader.join(timeout=2.0)
        if self.reader.is_alive():
            log(f"{self.spec.name} reader thread did not exit within 2s", "warn")


def _pump(cp_box: list[ComponentProc], fh) -> None:
    """Reader thread body. cp_box is a one-element list so we can pass the
    ComponentProc reference before it's constructed (chicken-and-egg with
    the Thread()). Closes fh on exit, guaranteed."""
    try:
        cp = cp_box[0]
        assert cp.proc.stdout is not None
        rx_ready = cp.spec.ready_regex
        rx_fail = cp.spec.fail_regex
        for raw in cp.proc.stdout:
            fh.write(raw)
            fh.flush()
            line = raw.decode("utf-8", errors="replace")
            if rx_ready and not cp.ready_event.is_set() and rx_ready.search(line):
                cp.ready_event.set()
            if rx_fail and rx_fail.search(line):
                cp.fail_event.set()
    finally:
        fh.close()


@contextlib.contextmanager
def running(spec: ComponentSpec):
    """Start spec, yield ComponentProc, guarantee stop() on exit (any path)."""
    log(f"start {spec.name}: {' '.join(spec.argv)}")
    log_path = LOG_DIR / f"{spec.name}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(log_path, "wb")
    try:
        proc = subprocess.Popen(
            spec.argv,
            cwd=str(spec.cwd) if spec.cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
    except BaseException:
        fh.close()
        raise

    cp_box: list[ComponentProc] = []
    reader = threading.Thread(
        target=_pump, args=(cp_box, fh), daemon=True, name=f"reader-{spec.name}"
    )
    cp = ComponentProc(spec=spec, proc=proc, log_path=log_path, reader=reader)
    cp_box.append(cp)
    reader.start()

    try:
        yield cp
    finally:
        cp.stop()


# ---------- signal handling ----------

class _Interrupted(SystemExit):
    """Raised from a signal handler so context-manager `finally` blocks run."""


def _signal_handler(signum, _frame):
    # Just raise — every component is held inside a `with running(...)` block
    # whose __exit__ will run cleanup. No global state, no double-teardown,
    # no reentrancy concerns.
    raise _Interrupted(128 + signum)


for _sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(_sig, _signal_handler)


# ---------- preflight ----------

def require_root() -> None:
    if os.geteuid() != 0:
        die("must run as root")


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def sctp_listening(host: str, port: int) -> bool:
    out = subprocess.run(
        ["ss", "-A", "sctp", "-ln"], capture_output=True, text=True, check=False
    ).stdout
    return f"{host}:{port}" in out


def mongosh_ping() -> bool:
    """True iff mongosh can complete `db.adminCommand('ping')`.

    Matches the readiness probe used by the official MongoDB Docker image's
    entrypoint. Robust across mongod versions (log format changed to JSON
    in 4.4+); a TCP connect is not sufficient (port opens before the server
    accepts queries).
    """
    r = subprocess.run(
        [
            "mongosh", "--quiet",
            "--host", MONGO_HOST, "--port", str(MONGO_PORT),
            "--eval", "db.adminCommand('ping').ok",
        ],
        capture_output=True, text=True, check=False, timeout=2.0,
    )
    return r.returncode == 0 and r.stdout.strip().endswith("1")


def provision_subscriber(creds: UECreds, apn: str = "internet") -> None:
    """Upsert one subscriber doc into open5gs.subscribers via mongosh.

    Matches the schema written by open5gs-dbctl / the Open5GS WebUI: HSS
    reads `imsi` + `security.{k,opc,amf}` for AKA, and the `slice[0].session`
    list for APN→PGW resolution. Upsert (not insert) so re-running the
    runner against a persisted Mongo volume is idempotent — the same UE
    creds overwrite cleanly.

    `amf` is the Authentication Management Field, fixed at 0x8000 for LTE
    (per 3GPP TS 33.401, the high bit indicates "separation bit set").
    """
    doc = {
        "imsi": creds.imsi.value,
        "subscribed_rau_tau_timer": 12,
        "network_access_mode": 0,
        "subscriber_status": 0,
        "access_restriction_data": 32,
        "security": {
            "k": creds.k,
            "opc": creds.opc,
            "op": None,
            "amf": "8000",
        },
        "ambr": {
            "downlink": {"value": 1, "unit": 3},
            "uplink": {"value": 1, "unit": 3},
        },
        "slice": [{
            "sst": 1,
            "default_indicator": True,
            "session": [{
                "name": apn,
                "type": 3,
                "pcc_rule": [],
                "ambr": {
                    "downlink": {"value": 1, "unit": 3},
                    "uplink": {"value": 1, "unit": 3},
                },
                "qos": {
                    "index": 9,
                    "arp": {
                        "priority_level": 8,
                        "pre_emption_capability": 1,
                        "pre_emption_vulnerability": 1,
                    },
                },
            }],
        }],
    }
    script = (
        f"db.subscribers.updateOne("
        f"  {{imsi: {json.dumps(creds.imsi.value)}}},"
        f"  {{$set: {json.dumps(doc)}}},"
        f"  {{upsert: true}}"
        f")"
    )
    r = subprocess.run(
        [
            "mongosh", "--quiet",
            "--host", MONGO_HOST, "--port", str(MONGO_PORT),
            "open5gs", "--eval", script,
        ],
        capture_output=True, text=True, check=False, timeout=10.0,
    )
    if r.returncode != 0:
        die(f"subscriber provisioning failed: {r.stderr.strip() or r.stdout.strip()}")
    log(f"subscriber provisioned: imsi={creds.imsi.value} apn={apn}", "ok")


def preflight() -> None:
    """Validate config consistency before bringing anything up.

    Bound to the static config files only — does NOT check listeners or
    running processes, since we own the entire lifecycle now.
    """
    log("preflight: checking config consistency")
    enb_conf = CONFIG_DIR / "enb.conf"
    rr_conf = CONFIG_DIR / "rr.conf"
    ue_conf = CONFIG_DIR / "ue.conf"
    mme_conf = OPEN5GS_CONFIG_DIR / "mme.yaml"
    for p in (enb_conf, rr_conf, ue_conf, mme_conf, SRSENB_BIN, SRSUE_BIN, MONGOD_BIN):
        if not p.exists():
            die(f"missing: {p}")

    enb_plmn = parse_enb_plmn(enb_conf)
    enb_tac = parse_rr_tac(rr_conf)
    mme_plmn, mme_tac = parse_mme_plmn_tac(mme_conf)
    imsi = parse_ue_creds(ue_conf).imsi

    if enb_plmn != mme_plmn:
        die(f"PLMN mismatch: enb={enb_plmn}, mme={mme_plmn}")
    if enb_tac != mme_tac:
        die(f"TAC mismatch: enb rr.conf tac={enb_tac}, mme tai.tac={mme_tac}")
    if imsi.mcc != enb_plmn.mcc or imsi.mnc_for(enb_plmn) != enb_plmn.mnc:
        die(f"IMSI {imsi.value} PLMN prefix does not match {enb_plmn}")

    for p in ZMQ_PORTS:
        if not port_free(p):
            die(f"ZMQ port {p} already in use")

    log(f"preflight ok (plmn={enb_plmn}, tac={enb_tac}, imsi={imsi.value})", "ok")


# ---------- stack lifecycle (mongo + open5gs) ----------

def _mongo_spec() -> ComponentSpec:
    # No --logpath so mongod's log still reaches _pump (and logs/mongod.log).
    # Readiness is mongosh ping, not stderr grep — matches the official image.
    return ComponentSpec(
        name="mongod",
        argv=(
            str(MONGOD_BIN),
            "--dbpath", "/var/lib/mongodb",
            "--bind_ip", MONGO_HOST,
            "--port", str(MONGO_PORT),
        ),
        ready_check=mongosh_ping,
    )


def _open5gs_spec(daemon: str) -> ComponentSpec:
    """Build a ComponentSpec for one Open5GS daemon.

    No per-daemon readiness probe: the daemons start near-instantly and the
    only readiness that matters to the next stage (srsenb) is the MME's S1AP
    SCTP listener, gated explicitly at the end of _bring_up_core. Per-daemon
    health is just "process didn't immediately die" (caught by wait_ready).

    `daemon` is the short name ('mme', 'hss', ...). Binary lives at
    /usr/bin/open5gs-<daemon>d, YAML at /etc/open5gs/<daemon>.yaml (which is
    bind-mounted from configs/open5gs/<daemon>.yaml).
    """
    return ComponentSpec(
        name=f"open5gs-{daemon}",
        argv=(
            str(OPEN5GS_BIN_DIR / f"open5gs-{daemon}d"),
            "-c", f"/etc/open5gs/{daemon}.yaml",
        ),
    )


def _bring_up_core(stack: contextlib.ExitStack, ue_creds: UECreds) -> None:
    """Enter Mongo + 8 Open5GS daemons into the given ExitStack.

    Sequence: mongo → provision subscriber → 8 Open5GS daemons → wait for
    MME SCTP listener. Subscriber must exist before HSS first reads it
    (HSS only queries Mongo on demand, so timing is generous, but doing it
    pre-launch keeps the failure mode obvious).

    Bails out (via die) if any daemon doesn't reach ready within timeout —
    the ExitStack ensures already-started daemons are torn down on the way
    out of the caller's `with` block.
    """
    mongo = stack.enter_context(running(_mongo_spec()))
    if not mongo.wait_ready(timeout=20.0):
        _dump_log_tail(mongo.log_path)
        die("mongod did not become ready")
    log("mongod ready", "ok")

    provision_subscriber(ue_creds)

    # Launch all 8 daemons; no per-daemon readiness (they'd need YAML-derived
    # port probes — overkill). The MME SCTP gate below is the real signal.
    daemons = [stack.enter_context(running(_open5gs_spec(d))) for d in OPEN5GS_DAEMONS]

    # MME SCTP listener — the only readiness signal the next stage actually
    # depends on. Generous timeout because HSS Diameter peering with MME can
    # take a few seconds on cold start.
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        for cp in daemons:
            if cp.proc.poll() is not None:
                _dump_log_tail(cp.log_path)
                die(f"{cp.spec.name} died during core bring-up")
        if sctp_listening(MME_SCTP_HOST, MME_SCTP_PORT):
            log("open5gs core up; MME SCTP listening", "ok")
            return
        time.sleep(0.2)
    die(f"MME not listening on {MME_SCTP_HOST}:{MME_SCTP_PORT} after core start")


# ---------- capture pipeline ----------

def _tcpdump_spec(pcap_path: Path) -> ComponentSpec:
    return ComponentSpec(
        name="tcpdump",
        argv=(
            "tcpdump", "-i", "lo", "-s", "0",
            "-w", str(pcap_path),
            "-U",
            "sctp port 36412 or sctp port 36422",
        ),
        ready_regex=TCPDUMP_READY_REGEX,
    )


def _srsenb_spec() -> ComponentSpec:
    return ComponentSpec(
        name="srsenb",
        argv=(str(SRSENB_BIN), "./enb.conf"),
        cwd=CONFIG_DIR,
        ready_regex=ENB_READY_REGEX,
        fail_regex=S1_SETUP_FAIL_REGEX,
    )


def _srsue_spec() -> ComponentSpec:
    return ComponentSpec(
        name="srsue",
        argv=(str(SRSUE_BIN), "./ue.conf"),
        cwd=CONFIG_DIR,
        ready_regex=UE_ATTACH_REGEX,
    )


def run_capture(name: str, out_dir: Path, attach_timeout: float = 30.0) -> Path:
    require_root()
    preflight()

    ue_creds = parse_ue_creds(CONFIG_DIR / "ue.conf")

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    pcap_path = out_dir / f"{name}_{ts}.pcap"
    meta_path = pcap_path.with_suffix(".json")

    attached = False
    # ExitStack guarantees reverse-order teardown for every entered context,
    # whether we leave normally, by exception, or via a signal-raised _Interrupted.
    # Order: mongo → 8 open5gs daemons → tcpdump → srsenb → srsue.
    # Teardown unwinds the opposite way.
    with contextlib.ExitStack() as stack:
        _bring_up_core(stack, ue_creds)

        tcpdump = stack.enter_context(running(_tcpdump_spec(pcap_path)))
        if not tcpdump.wait_ready(timeout=5.0):
            _dump_log_tail(tcpdump.log_path)
            die("tcpdump did not start listening")

        enb = stack.enter_context(running(_srsenb_spec()))
        if not enb.wait_ready(timeout=15.0):
            _dump_log_tail(enb.log_path)
            if enb.fail_event.is_set():
                die("srsenb hit S1 Setup Failure")
            die("srsenb failed to reach ready state")
        log("srsenb ready, S1 established", "ok")

        ue = stack.enter_context(running(_srsue_spec()))
        attached = ue.wait_ready(timeout=attach_timeout)
        if not attached:
            _dump_log_tail(ue.log_path)
            log("attach did not complete in time", "err")
        else:
            log("attach successful", "ok")
            time.sleep(2.0)
        # ExitStack stops UE → eNB → tcpdump → open5gs → mongo here.

    enb_plmn = parse_enb_plmn(CONFIG_DIR / "enb.conf")
    meta = {
        "name": name,
        "timestamp": ts,
        "attached": attached,
        "plmn": {"mcc": enb_plmn.mcc, "mnc": enb_plmn.mnc},
        "imsi": ue_creds.imsi.value,
        "srsran_ref": os.environ.get("SRSRAN_REF"),
        "open5gs_version": os.environ.get("OPEN5GS_VERSION"),
        "mongo_version": os.environ.get("MONGO_VERSION"),
        "kernel": os.uname().release,
        "pcap_size_bytes": pcap_path.stat().st_size if pcap_path.exists() else 0,
    }
    meta_path.write_text(json.dumps(meta, indent=2))
    _chown_to_host(pcap_path, meta_path)
    log(f"pcap: {pcap_path}", "ok")
    log(f"meta: {meta_path}", "ok")
    return pcap_path


def _chown_to_host(*paths: Path) -> None:
    """Chown artifacts to $HOST_UID:$HOST_GID if those env vars are set.

    Container runs as root (srsenb/UPF/tcpdump need it). Without this, the
    bind-mounted captures/ ends up root-owned on the host, which is hostile
    to interactive use. HOST_UID/HOST_GID are injected by the Makefile.
    """
    uid_s = os.environ.get("HOST_UID")
    gid_s = os.environ.get("HOST_GID")
    if not (uid_s and gid_s):
        return
    uid, gid = int(uid_s), int(gid_s)
    for p in paths:
        if p.exists():
            os.chown(p, uid, gid)


# ---------- CLI ----------

def main() -> int:
    p = argparse.ArgumentParser(description="LTE testbed runner (container-internal)")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("capture", help="bring up stack, run attach, save pcap, tear down")
    c.add_argument("name", help="scenario name, used in pcap filename")
    c.add_argument("--attach-timeout", type=float, default=30.0)
    c.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_OUT_DIR,
        help=f"directory to write pcap + meta JSON (default: {DEFAULT_OUT_DIR})",
    )
    args = p.parse_args()

    if args.cmd == "capture":
        run_capture(args.name, out_dir=args.out_dir, attach_timeout=args.attach_timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
