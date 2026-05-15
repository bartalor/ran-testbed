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

LIVE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = LIVE_DIR / "configs"
OPEN5GS_CONFIG_DIR = CONFIG_DIR / "open5gs"
LOG_DIR = LIVE_DIR / "logs"
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
MONGO_READY_REGEX = re.compile(r"Waiting for connections", re.IGNORECASE)
# Open5GS daemons all print a line like "MME initialize...done" once their
# SCTP/GTPC/Diameter listeners are bound.
OPEN5GS_READY_REGEX = re.compile(r"initialize\.\.\.done", re.IGNORECASE)


# ---------- logging ----------

def log(msg: str, level: str = "info") -> None:
    ts = dt.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[x]"}.get(level, "[ ]")
    print(f"{ts} {prefix} {msg}", flush=True)


def die(msg: str, code: int = 1):
    log(msg, "err")
    sys.exit(code)


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


# ---------- config parsing ----------

_ENB_MCC_RE = re.compile(r"^\s*mcc\s*=\s*(\S+)\s*(?:#.*)?$")
_ENB_MNC_RE = re.compile(r"^\s*mnc\s*=\s*(\S+)\s*(?:#.*)?$")
_RR_TAC_RE = re.compile(r"^\s*tac\s*=\s*(\S+?);")
_UE_IMSI_RE = re.compile(r"^\s*imsi\s*=\s*(\d+)\s*(?:#.*)?$")
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


def parse_ue_imsi(path: Path) -> IMSI:
    imsis: list[str] = []
    for line in _uncommented_lines(path):
        if m := _UE_IMSI_RE.match(line):
            imsis.append(m.group(1))
    if len(imsis) != 1:
        die(f"{path}: expected exactly one active imsi=, got {imsis}")
    return IMSI(imsis[0])


# ---------- process supervision ----------

@dataclass(frozen=True)
class ComponentSpec:
    name: str
    argv: tuple[str, ...]
    cwd: Path | None = None
    ready_regex: re.Pattern[str] | None = None
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
        while time.monotonic() < deadline:
            if self.ready_event.is_set():
                return True
            if self.fail_event.is_set():
                return False
            if self.proc.poll() is not None:
                return False
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
    imsi = parse_ue_imsi(ue_conf)

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
    # In-container layout: /var/lib/mongodb for data, log to stderr (merged
    # into the per-component log file by _pump). --bind_ip 127.0.0.1 keeps it
    # off any external interface even if --net=host is used.
    return ComponentSpec(
        name="mongod",
        argv=(
            str(MONGOD_BIN),
            "--dbpath", "/var/lib/mongodb",
            "--bind_ip", MONGO_HOST,
            "--port", str(MONGO_PORT),
            "--logpath", "/var/log/mongodb/mongod.log",
            "--logappend",
        ),
        ready_regex=MONGO_READY_REGEX,
    )


def _open5gs_spec(daemon: str) -> ComponentSpec:
    """Build a ComponentSpec for one Open5GS daemon.

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
        ready_regex=OPEN5GS_READY_REGEX,
    )


def _bring_up_core(stack: contextlib.ExitStack) -> None:
    """Enter Mongo + 8 Open5GS daemons into the given ExitStack.

    Bails out (via die) if any daemon doesn't reach ready within timeout —
    the ExitStack ensures already-started daemons are torn down on the way
    out of the caller's `with` block.
    """
    mongo = stack.enter_context(running(_mongo_spec()))
    if not mongo.wait_ready(timeout=10.0):
        die("mongod did not become ready; see logs/mongod.log")
    log("mongod ready", "ok")

    for daemon in OPEN5GS_DAEMONS:
        cp = stack.enter_context(running(_open5gs_spec(daemon)))
        if not cp.wait_ready(timeout=10.0):
            die(f"open5gs-{daemon}d did not become ready; see logs/open5gs-{daemon}.log")

    # MME SCTP listener is the real readiness signal for the eNB to attach.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if sctp_listening(MME_SCTP_HOST, MME_SCTP_PORT):
            log("open5gs core up; MME SCTP listening", "ok")
            return
        time.sleep(0.1)
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
        _bring_up_core(stack)

        tcpdump = stack.enter_context(running(_tcpdump_spec(pcap_path)))
        if not tcpdump.wait_ready(timeout=5.0):
            die("tcpdump did not start listening; see logs/tcpdump.log")

        enb = stack.enter_context(running(_srsenb_spec()))
        if not enb.wait_ready(timeout=15.0):
            if enb.fail_event.is_set():
                die("srsenb hit S1 Setup Failure; see logs/srsenb.log")
            die("srsenb failed to reach ready state; see logs/srsenb.log")
        log("srsenb ready, S1 established", "ok")

        ue = stack.enter_context(running(_srsue_spec()))
        attached = ue.wait_ready(timeout=attach_timeout)
        if not attached:
            log("attach did not complete in time", "err")
        else:
            log("attach successful", "ok")
            time.sleep(2.0)
        # ExitStack stops UE → eNB → tcpdump → open5gs → mongo here.

    enb_plmn = parse_enb_plmn(CONFIG_DIR / "enb.conf")
    ue_imsi = parse_ue_imsi(CONFIG_DIR / "ue.conf")
    meta = {
        "name": name,
        "timestamp": ts,
        "attached": attached,
        "plmn": {"mcc": enb_plmn.mcc, "mnc": enb_plmn.mnc},
        "imsi": ue_imsi.value,
        "srsran_ref": os.environ.get("SRSRAN_REF"),
        "open5gs_version": os.environ.get("OPEN5GS_VERSION"),
        "mongo_version": os.environ.get("MONGO_VERSION"),
        "kernel": os.uname().release,
        "pcap_size_bytes": pcap_path.stat().st_size if pcap_path.exists() else 0,
    }
    meta_path.write_text(json.dumps(meta, indent=2))
    log(f"pcap: {pcap_path}", "ok")
    log(f"meta: {meta_path}", "ok")
    return pcap_path


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
