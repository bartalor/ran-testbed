#!/usr/bin/env python3
"""Live testbed runner for the LTE rogue-detector project.

Brings up Open5GS 4G core + srsenb + srsue over ZMQ, runs an attach, captures
S1AP traffic on loopback, tears the stack down. Designed to be safe against
the failure modes we already hit: stale srsenb retry loops, apparmor-confined
tcpdump, PLMN mismatches found at runtime.

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
import shutil
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

OPEN5GS_4G_UNITS = [
    "open5gs-nrfd",
    "open5gs-hssd",
    "open5gs-mmed",
    "open5gs-sgwcd",
    "open5gs-smfd",
    "open5gs-sgwud",
    "open5gs-upfd",
    "open5gs-pcrfd",
]

MME_SCTP_HOST = "127.0.0.2"
MME_SCTP_PORT = 36412
ZMQ_PORTS = (2000, 2001)

ATTACH_REGEX = re.compile(r"Network attach successful", re.IGNORECASE)
ENB_READY_REGEX = re.compile(r"eNodeB started", re.IGNORECASE)
S1_SETUP_FAIL_REGEX = re.compile(r"S1 Setup Failure", re.IGNORECASE)

PROCS: list["Component"] = []


# ---------- logging helpers ----------

def log(msg: str, level: str = "info") -> None:
    ts = dt.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[x]"}.get(level, "[ ]")
    print(f"{ts} {prefix} {msg}", flush=True)


def die(msg: str, code: int = 1) -> "NoReturn":  # type: ignore[name-defined]
    log(msg, "err")
    sys.exit(code)


# ---------- subprocess wrapper ----------

@dataclass
class Component:
    name: str
    argv: list[str]
    cwd: Path | None = None
    log_path: Path | None = None
    proc: subprocess.Popen | None = None
    ready_regex: re.Pattern | None = None
    fail_regex: re.Pattern | None = None
    ready_event: threading.Event = field(default_factory=threading.Event)
    fail_event: threading.Event = field(default_factory=threading.Event)
    attach_event: threading.Event = field(default_factory=threading.Event)
    _reader: threading.Thread | None = None

    def start(self) -> None:
        log(f"start {self.name}: {' '.join(self.argv)}")
        self.log_path = LOG_DIR / f"{self.name}.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            self.argv,
            cwd=str(self.cwd) if self.cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        self._reader = threading.Thread(
            target=self._pump, args=(fh,), daemon=True, name=f"reader-{self.name}"
        )
        self._reader.start()
        PROCS.append(self)

    def _pump(self, fh) -> None:
        assert self.proc and self.proc.stdout
        for raw in self.proc.stdout:
            fh.write(raw)
            fh.flush()
            try:
                line = raw.decode("utf-8", errors="replace")
            except Exception:
                continue
            if self.ready_regex and not self.ready_event.is_set() and self.ready_regex.search(line):
                self.ready_event.set()
            if self.fail_regex and self.fail_regex.search(line):
                self.fail_event.set()
            if ATTACH_REGEX.search(line):
                self.attach_event.set()
        fh.close()

    def wait_ready(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.ready_event.is_set():
                return True
            if self.fail_event.is_set():
                return False
            if self.proc and self.proc.poll() is not None:
                return False
            time.sleep(0.1)
        return False

    def stop(self, sig: int = signal.SIGTERM, timeout: float = 5.0) -> None:
        if not self.proc or self.proc.poll() is not None:
            return
        log(f"stop {self.name} (pid={self.proc.pid}, sig={sig})")
        try:
            os.killpg(os.getpgid(self.proc.pid), sig)
        except ProcessLookupError:
            return
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            log(f"{self.name} did not exit on SIGTERM, sending SIGKILL", "warn")
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                self.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                log(f"{self.name} ignored SIGKILL", "err")


# ---------- teardown ----------

def teardown_all() -> None:
    if not PROCS:
        return
    log("teardown: stopping launched components")
    for c in reversed(PROCS):
        c.stop()
    PROCS.clear()


def _signal_handler(signum, _frame) -> None:
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


def parse_enb_plmn(path: Path) -> tuple[str, str]:
    mcc = mnc = None
    for raw in path.read_text().splitlines():
        s = raw.strip()
        if s.startswith("#"):
            continue
        m = re.match(r"^mcc\s*=\s*(\S+)", s)
        if m:
            mcc = m.group(1)
        m = re.match(r"^mnc\s*=\s*(\S+)", s)
        if m:
            mnc = m.group(1)
    if not mcc or not mnc:
        die(f"could not parse mcc/mnc from {path}")
    return mcc, mnc  # type: ignore[return-value]


def parse_mme_plmn(path: Path) -> tuple[str, str]:
    # crude but sufficient: take first active mcc/mnc pair
    mcc = mnc = None
    for raw in path.read_text().splitlines():
        s = raw.strip()
        if s.startswith("#"):
            continue
        m = re.match(r"^mcc:\s*(\S+)", s)
        if m and mcc is None:
            mcc = m.group(1)
        m = re.match(r"^mnc:\s*(\S+)", s)
        if m and mnc is None:
            mnc = m.group(1)
    if not mcc or not mnc:
        die(f"could not parse plmn from {path}")
    return mcc, mnc  # type: ignore[return-value]


def parse_ue_imsi(path: Path) -> str:
    for raw in path.read_text().splitlines():
        s = raw.strip()
        if s.startswith("#"):
            continue
        m = re.match(r"^imsi\s*=\s*(\d+)", s)
        if m:
            return m.group(1)
    die(f"could not parse imsi from {path}")


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

    e_mcc, e_mnc = parse_enb_plmn(enb_conf)
    m_mcc, m_mnc = parse_mme_plmn(mme_conf)
    imsi = parse_ue_imsi(ue_conf)

    # IMSI MCC = first 3 digits, MNC = next 2 or 3 digits. enb.conf mnc may be
    # written as "01" while imsi uses "01". Normalize to int compare.
    def norm(x: str) -> str:
        return x.lstrip("0") or "0"

    if (norm(e_mcc), norm(e_mnc)) != (norm(m_mcc), norm(m_mnc)):
        die(
            f"PLMN mismatch: enb={e_mcc}/{e_mnc}, mme={m_mcc}/{m_mnc}. "
            f"Fix /etc/open5gs/mme.yaml (gummei + tai blocks) and restart open5gs-mmed."
        )

    imsi_mcc = imsi[:3]
    if norm(imsi_mcc) != norm(e_mcc):
        die(f"IMSI {imsi} does not start with enb mcc {e_mcc}")

    for p in ZMQ_PORTS:
        if not port_free(p):
            die(f"ZMQ port {p} already in use")

    if not sctp_listening(MME_SCTP_HOST, MME_SCTP_PORT):
        die(
            f"MME not listening on {MME_SCTP_HOST}:{MME_SCTP_PORT}. "
            f"Run: sudo python3 run.py up"
        )

    log(f"preflight ok (plmn={e_mcc}/{e_mnc}, imsi={imsi})", "ok")


# ---------- Open5GS lifecycle ----------

def systemctl(action: str, units: list[str]) -> None:
    log(f"systemctl {action}: {', '.join(units)}")
    subprocess.run(["systemctl", action, *units], check=True)


def core_up() -> None:
    require_root()
    if not sctp_listening(MME_SCTP_HOST, MME_SCTP_PORT):
        # mongodb is a dep of hssd; start it if not active
        if subprocess.run(["systemctl", "is-active", "--quiet", "mongod"]).returncode != 0:
            subprocess.run(["systemctl", "start", "mongod"], check=True)
        systemctl("start", OPEN5GS_4G_UNITS)
        # wait for MME listener
        for _ in range(50):
            if sctp_listening(MME_SCTP_HOST, MME_SCTP_PORT):
                break
            time.sleep(0.2)
        else:
            die("MME did not start listening within 10s")
    log("open5gs 4G core up", "ok")


def core_down() -> None:
    require_root()
    systemctl("stop", OPEN5GS_4G_UNITS)
    # leave mongod alone; cheap and other tools may use it
    log("open5gs 4G core down", "ok")


# ---------- capture pipeline ----------

def run_capture(name: str, attach_timeout: float = 30.0) -> Path:
    require_root()
    preflight()

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    pcap_path = PCAP_DIR / f"{name}_{ts}.pcap"
    meta_path = pcap_path.with_suffix(".json")

    tcpdump = Component(
        name="tcpdump",
        argv=[
            "tcpdump", "-i", "lo", "-s", "0",
            "-w", str(pcap_path),
            "-U",
            "sctp port 36412 or sctp port 36422",
        ],
    )
    tcpdump.start()
    # tcpdump prints "listening on lo" to stderr; we don't gate on it, just sleep a beat
    time.sleep(0.5)
    if tcpdump.proc and tcpdump.proc.poll() is not None:
        die("tcpdump failed to start; see logs/tcpdump.log")

    enb = Component(
        name="srsenb",
        argv=[str(SRSENB_BIN), "./enb.conf"],
        cwd=CONFIG_DIR,
        ready_regex=ENB_READY_REGEX,
        fail_regex=S1_SETUP_FAIL_REGEX,
    )
    enb.start()
    if not enb.wait_ready(timeout=15.0):
        die("srsenb failed to reach ready state; see logs/srsenb.log")
    if enb.fail_event.is_set():
        die("srsenb hit S1 Setup Failure; see logs/srsenb.log")
    log("srsenb ready, S1 established", "ok")

    ue = Component(
        name="srsue",
        argv=[str(SRSUE_BIN), "./ue.conf"],
        cwd=CONFIG_DIR,
    )
    ue.start()

    log(f"waiting up to {attach_timeout:.0f}s for attach")
    deadline = time.monotonic() + attach_timeout
    attached = False
    while time.monotonic() < deadline:
        if ue.attach_event.is_set() or enb.attach_event.is_set():
            attached = True
            break
        if ue.proc and ue.proc.poll() is not None:
            break
        time.sleep(0.2)

    if not attached:
        log("attach did not complete in time", "err")
    else:
        log("attach successful", "ok")
        # let a couple more S1AP messages flow
        time.sleep(2.0)

    teardown_all()

    meta = {
        "name": name,
        "timestamp": ts,
        "attached": attached,
        "plmn": parse_enb_plmn(CONFIG_DIR / "enb.conf"),
        "imsi": parse_ue_imsi(CONFIG_DIR / "ue.conf"),
        "srsran_commit": _git_commit("/home/bar/my_dev/srsRAN_4G"),
        "kernel": os.uname().release,
        "pcap_size_bytes": pcap_path.stat().st_size if pcap_path.exists() else 0,
    }
    meta_path.write_text(json.dumps(meta, indent=2))
    log(f"pcap: {pcap_path}", "ok")
    log(f"meta: {meta_path}", "ok")
    return pcap_path


def _git_commit(repo: str) -> str | None:
    if not Path(repo, ".git").exists():
        return None
    r = subprocess.run(
        ["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return r.stdout.strip() if r.returncode == 0 else None


# ---------- status ----------

def cmd_status() -> None:
    log("status")
    for u in OPEN5GS_4G_UNITS:
        r = subprocess.run(["systemctl", "is-active", u], capture_output=True, text=True)
        print(f"  {u:20s} {r.stdout.strip()}")
    print(f"  mme sctp listen     {'yes' if sctp_listening(MME_SCTP_HOST, MME_SCTP_PORT) else 'no'}")
    print(f"  zmq 2000 free       {'yes' if port_free(2000) else 'no'}")
    print(f"  zmq 2001 free       {'yes' if port_free(2001) else 'no'}")
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
