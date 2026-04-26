"""
SPECTRA — Phase 1 (Part B): Evidence Ingestion & Feature Extraction
=====================================================================
Parses raw evidence from:
  - File system artifacts (os / pathlib)
  - Windows Event Logs (.evtx via python-evtx)
  - Browser history (SQLite — Chrome/Firefox)
  - Network packets (.pcap via scapy)

Converts raw evidence → ML-ready feature dicts for the trained models.
Also applies rule-based scoring layer (hybrid intelligence).
"""

import os
import re
import json
import sqlite3
import hashlib
import logging
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("spectra.ingestion")

# ── Rule-based threat escalation table ───────────────────────────────────────
RULE_OVERRIDES = {
    # Process / filename patterns → instant high score
    "password_cracker":   95,
    "mimikatz":           98,
    "lazagne":            96,
    "pwdump":             95,
    "netpass":            90,
    "keefox":             85,
    "tor.exe":            80,
    "tor browser":        80,
    "wireshark":          55,  # legitimate but flagged
    "nmap":               70,
    "metasploit":         90,
    "cobaltstrike":       99,
    "Empire.ps1":         92,
    "powershell -enc":    75,  # encoded PS commands
    "base64":             45,  # context-dependent
}

RISKY_EXTENSIONS = {
    ".exe", ".bat", ".ps1", ".vbs", ".hta", ".scr",
    ".pif", ".com", ".cmd", ".jar", ".js", ".wsf",
}

SAFE_EXTENSIONS = {
    ".txt", ".jpg", ".png", ".pdf", ".docx",
    ".xlsx", ".csv", ".html", ".mp4", ".mp3",
}

# ── 1. File System Evidence ───────────────────────────────────────────────────

class FileSystemParser:
    """Scans a directory and extracts forensic artifacts."""

    def parse(self, root_path: str, max_depth: int = 4) -> list[dict]:
        artifacts = []
        root = Path(root_path)
        if not root.exists():
            log.warning(f"Path does not exist: {root_path}")
            return artifacts

        for item in self._walk(root, max_depth):
            artifact = self._analyze_file(item)
            if artifact:
                artifacts.append(artifact)

        log.info(f"File system scan: {len(artifacts)} artifacts from {root_path}")
        return artifacts

    def _walk(self, root: Path, max_depth: int):
        for dirpath, dirnames, filenames in os.walk(root):
            depth = len(Path(dirpath).relative_to(root).parts)
            if depth >= max_depth:
                dirnames.clear()
            for fname in filenames:
                yield Path(dirpath) / fname

    def _analyze_file(self, path: Path) -> Optional[dict]:
        try:
            stat = path.stat()
            ext = path.suffix.lower()
            name_lower = path.name.lower()

            # Rule-based risk check
            rule_score = 0
            for pattern, score in RULE_OVERRIDES.items():
                if pattern.lower() in name_lower:
                    rule_score = max(rule_score, score)

            is_risky = ext in RISKY_EXTENSIONS
            is_safe = ext in SAFE_EXTENSIONS

            artifact = {
                "type":          "file",
                "path":          str(path),
                "name":          path.name,
                "extension":     ext,
                "size_bytes":    stat.st_size,
                "created_at":    datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
                "modified_at":   datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "accessed_at":   datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat(),
                "sha256":        self._hash_file(path),
                "rule_score":    rule_score,
                "risk_flag":     "high" if rule_score > 70 else ("medium" if is_risky else "low"),

                # ML feature vector
                "features": {
                    "network_activity":   0.0,
                    "session_time":       0.0,
                    "data_transfer":      min(stat.st_size / 100_000_000, 1.0),
                    "connection_status":  2 if rule_score > 80 else (1 if is_risky else 0),
                },
            }
            return artifact
        except (PermissionError, OSError) as e:
            log.debug(f"Skipping {path}: {e}")
            return None

    @staticmethod
    def _hash_file(path: Path, chunk: int = 65536) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while data := f.read(chunk):
                    h.update(data)
        except (PermissionError, OSError):
            return ""
        return h.hexdigest()


# ── 2. Windows Event Log Parser ───────────────────────────────────────────────

class EventLogParser:
    """Parses .evtx files using python-evtx."""

    SUSPICIOUS_EVENT_IDS = {
        4625,   # failed logon
        4648,   # explicit credentials logon
        4720,   # user account created
        4723,   # password change attempt
        4776,   # NTLM auth
        4688,   # process creation
        7045,   # new service installed
        1102,   # audit log cleared
        4698,   # scheduled task created
    }

    def parse(self, evtx_path: str) -> list[dict]:
        artifacts = []
        try:
            import Evtx.Evtx as evtx
            import Evtx.Views as e_views
        except ImportError:
            log.warning("python-evtx not installed. Skipping EVTX parsing.")
            log.warning("Install with: pip install python-evtx")
            return self._mock_events()

        try:
            with evtx.Evtx(evtx_path) as log_file:
                for record in log_file.records():
                    artifact = self._parse_record(record)
                    if artifact:
                        artifacts.append(artifact)
        except Exception as e:
            log.error(f"Error parsing {evtx_path}: {e}")

        log.info(f"Event log: {len(artifacts)} events from {evtx_path}")
        return artifacts

    def _parse_record(self, record) -> Optional[dict]:
        try:
            xml = record.xml()
            event_id = self._extract_xml_value(xml, "EventID")
            timestamp = self._extract_xml_value(xml, "TimeCreated SystemTime")
            computer = self._extract_xml_value(xml, "Computer")
            user = self._extract_xml_value(xml, "SubjectUserName") or "SYSTEM"

            eid = int(event_id) if event_id else 0
            is_suspicious = eid in self.SUSPICIOUS_EVENT_IDS

            # Anomalous login time (2 AM – 5 AM)
            login_anomaly = 0.0
            if timestamp:
                try:
                    ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    if 2 <= ts.hour <= 5:
                        login_anomaly = 1.0
                except ValueError:
                    pass

            rule_score = 80 if eid in {1102, 4698, 7045} else (60 if is_suspicious else 0)

            return {
                "type":       "event_log",
                "event_id":   eid,
                "timestamp":  timestamp,
                "computer":   computer,
                "user":       user,
                "suspicious": is_suspicious,
                "rule_score": rule_score,

                "features": {
                    "network_activity":   0.1 if is_suspicious else 0.0,
                    "session_time":       login_anomaly,
                    "data_transfer":      0.0,
                    "connection_status":  2 if rule_score > 70 else (1 if is_suspicious else 0),
                },
            }
        except Exception:
            return None

    @staticmethod
    def _extract_xml_value(xml: str, tag: str) -> str:
        match = re.search(rf"<{re.escape(tag)}[^>]*>([^<]+)<", xml)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _mock_events() -> list[dict]:
        """Returns sample events when python-evtx is unavailable (for testing)."""
        return [
            {
                "type": "event_log", "event_id": 4625, "timestamp": "2024-01-15T03:14:00Z",
                "computer": "WORKSTATION-01", "user": "admin", "suspicious": True, "rule_score": 60,
                "features": {"network_activity": 0.1, "session_time": 1.0, "data_transfer": 0.0, "connection_status": 1},
            },
            {
                "type": "event_log", "event_id": 1102, "timestamp": "2024-01-15T03:15:00Z",
                "computer": "WORKSTATION-01", "user": "SYSTEM", "suspicious": True, "rule_score": 80,
                "features": {"network_activity": 0.2, "session_time": 1.0, "data_transfer": 0.0, "connection_status": 2},
            },
        ]


# ── 3. Browser History Parser ─────────────────────────────────────────────────

class BrowserHistoryParser:
    """Extracts browsing history from Chrome/Firefox SQLite databases."""

    SUSPICIOUS_DOMAINS = [
        "torproject.org", "ahmia.fi", "onion",
        "pastebin.com", "anonfiles.com", "zerobin.net",
        "protonmail.com",  # not malicious but flagged for context
        "dark.", "underground", "hxxp",
    ]

    def parse_chrome(self, history_path: str) -> list[dict]:
        """Chrome: ~/AppData/Local/Google/Chrome/User Data/Default/History"""
        return self._parse_sqlite(
            history_path,
            query="SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC",
            browser="chrome",
        )

    def parse_firefox(self, history_path: str) -> list[dict]:
        """Firefox: ~/.mozilla/firefox/PROFILE/places.sqlite"""
        return self._parse_sqlite(
            history_path,
            query="""
                SELECT p.url, p.title, p.visit_count, h.visit_date
                FROM moz_places p JOIN moz_historyvisits h ON p.id = h.place_id
                ORDER BY h.visit_date DESC
            """,
            browser="firefox",
        )

    def _parse_sqlite(self, db_path: str, query: str, browser: str) -> list[dict]:
        artifacts = []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True)
            cursor = conn.execute(query)
            for row in cursor.fetchall():
                artifact = self._analyze_visit(row, browser)
                if artifact:
                    artifacts.append(artifact)
            conn.close()
        except sqlite3.Error as e:
            log.warning(f"Browser DB error ({db_path}): {e}")
            return self._mock_history()

        log.info(f"Browser history ({browser}): {len(artifacts)} entries")
        return artifacts

    def _analyze_visit(self, row, browser: str) -> Optional[dict]:
        url = str(row[0] or "")
        title = str(row[1] or "")
        visit_count = int(row[2] or 0)
        timestamp_raw = row[3]

        # Convert browser-specific timestamp to ISO
        timestamp = self._convert_timestamp(timestamp_raw, browser)

        # Check for suspicious domains
        risk_flag = "low"
        rule_score = 0
        for domain in self.SUSPICIOUS_DOMAINS:
            if domain.lower() in url.lower():
                risk_flag = "high"
                rule_score = 75
                break

        # TOR detection
        if ".onion" in url or "torproject.org" in url:
            rule_score = max(rule_score, 80)

        return {
            "type":        "browser_history",
            "url":         url,
            "title":       title,
            "visit_count": visit_count,
            "timestamp":   timestamp,
            "risk_flag":   risk_flag,
            "rule_score":  rule_score,
            "browser":     browser,

            "features": {
                "network_activity":   min(visit_count / 100, 1.0),
                "session_time":       0.0,
                "data_transfer":      0.0,
                "connection_status":  2 if rule_score > 70 else (1 if risk_flag == "medium" else 0),
            },
        }

    @staticmethod
    def _convert_timestamp(raw, browser: str) -> str:
        try:
            if browser == "chrome" and raw:
                # Chrome: microseconds since 1601-01-01
                epoch_diff = 11_644_473_600  # seconds between 1601 and 1970
                ts = datetime.fromtimestamp((raw / 1_000_000) - epoch_diff, tz=timezone.utc)
                return ts.isoformat()
            elif browser == "firefox" and raw:
                # Firefox: microseconds since Unix epoch
                ts = datetime.fromtimestamp(raw / 1_000_000, tz=timezone.utc)
                return ts.isoformat()
        except (ValueError, OSError, OverflowError):
            pass
        return datetime.now(tz=timezone.utc).isoformat()

    @staticmethod
    def _mock_history() -> list[dict]:
        return [
            {
                "type": "browser_history", "url": "https://torproject.org",
                "title": "Tor Project", "visit_count": 12,
                "timestamp": "2024-01-15T02:30:00+00:00",
                "risk_flag": "high", "rule_score": 80, "browser": "chrome",
                "features": {"network_activity": 0.12, "session_time": 0.0, "data_transfer": 0.0, "connection_status": 2},
            },
            {
                "type": "browser_history", "url": "https://pastebin.com/raw/xK9mA",
                "title": "Pastebin", "visit_count": 3,
                "timestamp": "2024-01-15T02:45:00+00:00",
                "risk_flag": "medium", "rule_score": 50, "browser": "chrome",
                "features": {"network_activity": 0.03, "session_time": 0.0, "data_transfer": 0.0, "connection_status": 1},
            },
        ]


# ── 4. Network Packet Parser (.pcap) ──────────────────────────────────────────

class NetworkPacketParser:
    """Parses .pcap files using scapy."""

    SUSPICIOUS_PORTS = {22, 23, 3389, 4444, 1337, 6667, 31337}

    def parse(self, pcap_path: str) -> list[dict]:
        try:
            from scapy.all import rdpcap, IP, TCP, UDP
        except ImportError:
            log.warning("scapy not installed. Skipping PCAP parsing.")
            log.warning("Install with: pip install scapy")
            return self._mock_packets()

        artifacts = []
        try:
            packets = rdpcap(pcap_path)
            for pkt in packets:
                artifact = self._analyze_packet(pkt)
                if artifact:
                    artifacts.append(artifact)
        except Exception as e:
            log.error(f"PCAP error ({pcap_path}): {e}")
            return self._mock_packets()

        log.info(f"PCAP: {len(artifacts)} packets from {pcap_path}")
        return artifacts

    def _analyze_packet(self, pkt) -> Optional[dict]:
        try:
            from scapy.all import IP, TCP, UDP
            if IP not in pkt:
                return None

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = pkt[IP].proto
            size = len(pkt)
            timestamp = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat()

            port = 0
            if TCP in pkt:
                port = pkt[TCP].dport
            elif UDP in pkt:
                port = pkt[UDP].dport

            suspicious_port = port in self.SUSPICIOUS_PORTS
            private_src = self._is_private(src_ip)
            rule_score = 70 if port == 4444 else (60 if suspicious_port else 0)

            return {
                "type":           "network_packet",
                "src_ip":         src_ip,
                "dst_ip":         dst_ip,
                "dst_port":       port,
                "protocol":       proto,
                "size_bytes":     size,
                "timestamp":      timestamp,
                "suspicious_port":suspicious_port,
                "rule_score":     rule_score,

                "features": {
                    "network_activity":   min(size / 65535, 1.0),
                    "session_time":       0.0,
                    "data_transfer":      min(size / 100_000, 1.0),
                    "connection_status":  2 if rule_score > 60 else (1 if suspicious_port else 0),
                },
            }
        except Exception:
            return None

    @staticmethod
    def _is_private(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first, second = int(parts[0]), int(parts[1])
            return (first == 10 or (first == 172 and 16 <= second <= 31)
                    or (first == 192 and second == 168))
        except ValueError:
            return False

    @staticmethod
    def _mock_packets() -> list[dict]:
        return [
            {
                "type": "network_packet", "src_ip": "192.168.1.50", "dst_ip": "185.220.101.1",
                "dst_port": 4444, "protocol": 6, "size_bytes": 1024,
                "timestamp": "2024-01-15T02:00:00+00:00",
                "suspicious_port": True, "rule_score": 70,
                "features": {"network_activity": 0.5, "session_time": 0.0, "data_transfer": 0.01, "connection_status": 2},
            },
        ]


# ── 5. Hybrid Intelligence: Merge ML + Rules ──────────────────────────────────

def compute_final_score(ml_score: int, rule_score: int) -> int:
    """
    Weighted combination of ML prediction (60%) + rule-based score (40%).
    Returns 0-100.
    """
    final = (ml_score * 0.6) + (rule_score * 0.4)
    return min(100, int(round(final)))


def classify_severity(score: int) -> str:
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    elif score >= 20:
        return "low"
    return "informational"


# ── 6. Evidence Collector ─────────────────────────────────────────────────────

class EvidenceCollector:
    """
    Top-level orchestrator. Collects all evidence types and returns
    a unified list of artifacts with features attached.
    """

    def __init__(self):
        self.fs_parser      = FileSystemParser()
        self.evtx_parser    = EventLogParser()
        self.browser_parser = BrowserHistoryParser()
        self.pcap_parser    = NetworkPacketParser()

    def collect(self, config: dict) -> list[dict]:
        """
        config keys (all optional):
          fs_path, evtx_path, chrome_history, firefox_history, pcap_path
        """
        all_artifacts = []

        if path := config.get("fs_path"):
            all_artifacts.extend(self.fs_parser.parse(path))

        if path := config.get("evtx_path"):
            all_artifacts.extend(self.evtx_parser.parse(path))

        if path := config.get("chrome_history"):
            all_artifacts.extend(self.browser_parser.parse_chrome(path))

        if path := config.get("firefox_history"):
            all_artifacts.extend(self.browser_parser.parse_firefox(path))

        if path := config.get("pcap_path"):
            all_artifacts.extend(self.pcap_parser.parse(path))

        log.info(f"Total artifacts collected: {len(all_artifacts)}")
        return all_artifacts


# ── Standalone test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    collector = EvidenceCollector()

    # Demo: scan current directory
    artifacts = collector.collect({
        "fs_path": str(Path.cwd()),
    })
    # Add mock browser + pcap data
    artifacts.extend(BrowserHistoryParser()._mock_history())
    artifacts.extend(NetworkPacketParser()._mock_packets())
    artifacts.extend(EventLogParser()._mock_events())

    print(f"\n✔ Collected {len(artifacts)} artifacts")
    for a in artifacts[:5]:
        print(json.dumps(a, indent=2, default=str))
