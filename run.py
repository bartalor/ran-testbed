#!/usr/bin/env python3
"""Live testbed runner for the LTE rogue-detector project.

Brings up Open5GS 4G core + srsenb + srsue over ZMQ, runs an attach, captures
S1AP traffic on loopback, tears the stack down.

Run as root (it needs to start systemd units, launch srsenb/srsue/tcpdump):
    sudo python3 run.py capture legit_attach
    sudo python3 run.py status
    sudo python3 run.py down
"""

from __future__ import annotations

import argparse
import atexit
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

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LIVE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = LIVE_DIR / "configs"
LOG_DIR = LIVE_DIR / "logs"
PCAP_DIR = PROJECT_ROOT / "sample_pcaps"

SRSENB_BIN = Path("/home/bar/my_dev/srsRAN_4G/build/srsenb/src/srsenb")
SRSUE_BIN = Path("/home/bar/my_dev/srsRAN_4G/build/srsue/src/srsue")

OPEN5GS_4G_UNITS = (
    "open5gs-nrfd",
    "open5gs-hssd",
    "open5gs-mmed",
    "open5gs-sgwcd",
    "open5gs-smfd",
    "open5gs-sgwud",
    "open5gs-upfd",
    "open5gs-pcrfd",
)

MME_SCTP_HOST = "127.0.0.2"
MME_SCTP_PORT = 36412
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
_UE_IMSI_RE = re.compile(r"^\s*imsi\s*=\s*(\d+)\s*(?:#.*)?$")
_YAML_MCC_RE = re.compile(r"^\s*mcc:\s*(\S+)\s*$")
_YAML_MNC_RE = re.compile(r"^\s*mnc:\s*(\S+)\s*$")


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


def parse_mme_plmn(path: Path) -> PLMN:
    """Active gummei+tai PLMN blocks in mme.yaml. Both must exist and agree."""
    plmns: list[PLMN] = []
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
    if pending_mcc is not None:
        die(f"{path}: trailing mcc {pending_mcc!r} with no matching mnc")
    if len(plmns) < 2:
        die(f"{path}: expected at least 2 active PLMN blocks (gummei + tai), got {plmns}")
    if len(set(plmns)) != 1:
        die(f"{path}: PLMN blocks disagree: {plmns}")
    return plmns[0]


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
    ready_event: threading.Event = field(default_factory=threading.Event)
    fail_event: threading.Event = field(default_factory=threading.Event)
    _reader: threading.Thread | None = None

    def _pump(self, fh) -> None:
        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            fh.write(raw)
            fh.flush()
            line = raw.decode("utf-8", errors="replace")
            rx_ready = self.spec.ready_regex
            rx_fail = self.spec.fail_regex
            if rx_ready and not self.ready_event.is_set() and rx_ready.search(line):
                self.ready_event.set()
            if rx_fail and rx_fail.search(line):
                self.fail_event.set()
        fh.close()

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

    def stop(self, sig: int = signal.SIGTERM, timeout: float = 5.0) -> None:
        if self.proc.poll() is not None:
            return
        log(f"stop {self.spec.name} (pid={self.proc.pid}, sig={sig})")
        try:
            os.killpg(os.getpgid(self.proc.pid), sig)
        except ProcessLookupError:
            return
        try:
            self.proc.wait(timeout=timeout)
            return
        except subprocess.TimeoutExpired:
            log(f"{self.spec.name} did not exit on SIGTERM, sending SIGKILL", "warn")
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            return
        try:
            self.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            log(f"{self.spec.name} ignored SIGKILL", "err")


PROCS: list[ComponentProc] = []


def start(spec: ComponentSpec) -> ComponentProc:
    log(f"start {spec.name}: {' '.join(spec.argv)}")
    log_path = LOG_DIR / f"{spec.name}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(log_path, "wb")
    proc = subprocess.Popen(
        spec.argv,
        cwd=str(spec.cwd) if spec.cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )
    cp = ComponentProc(spec=spec, proc=proc, log_path=log_path)
    cp._reader = threading.Thread(
        target=cp._pump, args=(fh,), daemon=True, name=f"reader-{spec.name}"
    )
    cp._reader.start()
    PROCS.append(cp)
    return cp


# ---------- teardown ----------

def teardown_all() -> None:
    if not PROCS:
        return
    log("teardown: stopping launched components")
    for c in reversed(PROCS):
        c.stop()
    PROCS.clear()


def _signal_handler(signum, _frame):
    log(f"caught signal {signum}, tearing down", "warn")
    teardown_all()
    sys.exit(128 + signum)


atexit.register(teardown_all)
for _sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(_sig, _signal_handler)


# ---------- preflight ----------

def require_root() -> None:
    if os.geteuid() != 0:
        die("must run as root (sudo python3 run.py ...)")


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
    log("preflight: checking environment")
    enb_conf = CONFIG_DIR / "enb.conf"
    ue_conf = CONFIG_DIR / "ue.conf"
    mme_conf = Path("/etc/open5gs/mme.yaml")
    for p in (enb_conf, ue_conf, mme_conf, SRSENB_BIN, SRSUE_BIN):
        if not p.exists():
            die(f"missing: {p}")

    enb_plmn = parse_enb_plmn(enb_conf)
    mme_plmn = parse_mme_plmn(mme_conf)
    imsi = parse_ue_imsi(ue_conf)

    if enb_plmn != mme_plmn:
        die(
            f"PLMN mismatch: enb={enb_plmn}, mme={mme_plmn}. "
            f"Edit /etc/open5gs/mme.yaml (gummei + tai blocks) and restart open5gs-mmed."
        )

    if imsi.mcc != enb_plmn.mcc or imsi.mnc_for(enb_plmn) != enb_plmn.mnc:
        die(f"IMSI {imsi.value} PLMN prefix does not match {enb_plmn}")

    for p in ZMQ_PORTS:
        if not port_free(p):
            die(f"ZMQ port {p} already in use")

    if not sctp_listening(MME_SCTP_HOST, MME_SCTP_PORT):
        die(f"MME not listening on {MME_SCTP_HOST}:{MME_SCTP_PORT}. Run: sudo python3 run.py up")

    log(f"preflight ok (plmn={enb_plmn}, imsi={imsi.value})", "ok")


# ---------- Open5GS lifecycle ----------

def systemctl(action: str, units: tuple[str, ...]) -> None:
    log(f"systemctl {action}: {', '.join(units)}")
    subprocess.run(["systemctl", action, *units], check=True)


def _all_units_active(units: tuple[str, ...]) -> bool:
    r = subprocess.run(
        ["systemctl", "is-active", *units], capture_output=True, text=True, check=False
    )
    return all(line.strip() == "active" for line in r.stdout.splitlines())


def core_up() -> None:
    require_root()
    if subprocess.run(["systemctl", "is-active", "--quiet", "mongod"]).returncode != 0:
        subprocess.run(["systemctl", "start", "mongod"], check=True)
    systemctl("start", OPEN5GS_4G_UNITS)
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if _all_units_active(OPEN5GS_4G_UNITS) and sctp_listening(MME_SCTP_HOST, MME_SCTP_PORT):
            log("open5gs 4G core up", "ok")
            return
        time.sleep(0.2)
    die("open5gs 4G core did not become ready within 10s")


def core_down() -> None:
    require_root()
    systemctl("stop", OPEN5GS_4G_UNITS)
    log("open5gs 4G core down", "ok")


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


def run_capture(name: str, attach_timeout: float = 30.0) -> Path:
    require_root()
    preflight()

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    pcap_path = PCAP_DIR / f"{name}_{ts}.pcap"
    meta_path = pcap_path.with_suffix(".json")

    tcpdump = start(_tcpdump_spec(pcap_path))
    if not tcpdump.wait_ready(timeout=5.0):
        die("tcpdump did not start listening; see logs/tcpdump.log")

    enb = start(_srsenb_spec())
    if not enb.wait_ready(timeout=15.0):
        if enb.fail_event.is_set():
            die("srsenb hit S1 Setup Failure; see logs/srsenb.log")
        die("srsenb failed to reach ready state; see logs/srsenb.log")
    log("srsenb ready, S1 established", "ok")

    ue = start(_srsue_spec())
    attached = ue.wait_ready(timeout=attach_timeout)
    if not attached:
        log("attach did not complete in time", "err")
    else:
        log("attach successful", "ok")
        time.sleep(2.0)

    teardown_all()

    enb_plmn = parse_enb_plmn(CONFIG_DIR / "enb.conf")
    ue_imsi = parse_ue_imsi(CONFIG_DIR / "ue.conf")
    meta = {
        "name": name,
        "timestamp": ts,
        "attached": attached,
        "plmn": {"mcc": enb_plmn.mcc, "mnc": enb_plmn.mnc},
        "imsi": ue_imsi.value,
        "srsran_commit": _git_commit(Path("/home/bar/my_dev/srsRAN_4G")),
        "kernel": os.uname().release,
        "pcap_size_bytes": pcap_path.stat().st_size if pcap_path.exists() else 0,
    }
    meta_path.write_text(json.dumps(meta, indent=2))
    log(f"pcap: {pcap_path}", "ok")
    log(f"meta: {meta_path}", "ok")
    return pcap_path


def _git_commit(repo: Path) -> str | None:
    if not (repo / ".git").exists():
        return None
    r = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return r.stdout.strip() if r.returncode == 0 else None


# ---------- status ----------

def cmd_status() -> None:
    log("status")
    for u in OPEN5GS_4G_UNITS:
        r = subprocess.run(["systemctl", "is-active", u], capture_output=True, text=True)
        print(f"  {u:20s} {r.stdout.strip()}")
    print(f"  mme sctp listen     {'yes' if sctp_listening(MME_SCTP_HOST, MME_SCTP_PORT) else 'no'}")
    for p in ZMQ_PORTS:
        print(f"  zmq {p} free       {'yes' if port_free(p) else 'no'}")
    stragglers = subprocess.run(
        ["pgrep", "-af", "srsenb|srsue|tcpdump.*legit_attach"], capture_output=True, text=True
    ).stdout.strip()
    print(f"  stragglers          {stragglers or 'none'}")


# ---------- CLI ----------

def main() -> int:
    p = argparse.ArgumentParser(description="LTE testbed runner")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("up", help="start Open5GS 4G core")
    sub.add_parser("down", help="stop Open5GS 4G core")
    sub.add_parser("status", help="show stack status")
    c = sub.add_parser("capture", help="run attach scenario and save pcap")
    c.add_argument("name", help="scenario name, used in pcap filename")
    c.add_argument("--attach-timeout", type=float, default=30.0)
    args = p.parse_args()

    if args.cmd == "up":
        core_up()
    elif args.cmd == "down":
        core_down()
    elif args.cmd == "status":
        cmd_status()
    elif args.cmd == "capture":
        run_capture(args.name, attach_timeout=args.attach_timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
