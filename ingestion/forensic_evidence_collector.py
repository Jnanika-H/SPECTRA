"""
SPECTRA Forensic Evidence Collector
====================================
Orchestrates evidence collection from forensic disk images.
Works alongside the existing evidence_collector.py for backward compatibility.
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Optional

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from forensic_image.image_detector import detect_image_format, find_image_segments, get_image_info, validate_segments, check_ewf_completeness
from forensic_image.evidence_source import ForensicImageSource
from evidence_collector import (
    FileSystemParser, EventLogParser, BrowserHistoryParser,
    NetworkPacketParser, log as evidence_log
)

log = logging.getLogger("spectra.forensic_collector")


class ForensicEvidenceCollector:
    """
    Collects artifacts from forensic disk images.
    Reuses existing parsers through the evidence source abstraction.
    """
    
    def __init__(self):
        self.browser_parser = BrowserHistoryParser()
        self.evtx_parser = EventLogParser()
        self.pcap_parser = NetworkPacketParser()
    
    def collect_from_image(self, config: Dict) -> Dict:
        """
        Collect evidence from a forensic disk image.
        
        Args:
            config: Dict with keys:
                - case_id: Case identifier
                - image_path: Path to first segment
                - max_files: Maximum files to process (default: 1000)
                - extract_browser: Extract browser artifacts (default: True)
                - extract_evtx: Extract Windows event logs (default: True)
                
        Returns:
            Dict with:
                - artifacts: List of artifact dicts
                - metadata: Source metadata
                - status: "success" or "error"
                - error: Error message if status="error"
        """
        case_id = config.get("case_id", "UNKNOWN")
        image_path = config.get("image_path")
        max_files = config.get("max_files", 1000)
        extract_browser = config.get("extract_browser", True)
        extract_evtx = config.get("extract_evtx", True)
        
        if not image_path:
            return {"status": "error", "error": "No image_path provided"}
        
        log.info(f"Starting forensic image collection: {case_id}")
        log.info(f"Image path: {image_path}")
        
        try:
            # Step 1: Detect image format and segments
            log.info("Detecting image format...")
            image_format = detect_image_format(image_path)
            
            if image_format == "UNKNOWN":
                return {
                    "status": "error",
                    "error": f"Unsupported or unrecognized image format: {image_path}"
                }
            
            log.info(f"Detected format: {image_format}")
            
            # Step 2: Find all segments
            segments = find_image_segments(image_path)
            log.info(f"Found {len(segments)} segment(s)")
            
            # Step 3: Validate segments exist
            is_valid, error_msg = validate_segments(segments)
            if not is_valid:
                return {"status": "error", "error": error_msg}
            
            # Step 4: Check EWF completeness using forensic library
            if image_format == "E01/EWF":
                log.info("Checking EWF image completeness...")
                is_complete, completeness_error = check_ewf_completeness(segments)
                
                if not is_complete:
                    return {
                        "status": "error",
                        "error": f"Incomplete EWF image: {completeness_error}. Please select all required segments (E01, E02, E03, etc.)"
                    }
                
                log.info("✓ EWF image is complete and valid")
            
            # Step 5: Open forensic image source
            log.info("Opening forensic image...")
            
            try:
                source = ForensicImageSource(case_id, image_path, image_format, segments)
            except Exception as e:
                error_str = str(e)
                if "Failed to open filesystem" in error_str:
                    # Provide helpful error message
                    return {
                        "status": "error",
                        "error": "Cannot open filesystem in forensic image. This may indicate: (1) Image is corrupt/incomplete, (2) Missing E01 segments - ensure ALL segments uploaded, (3) Unsupported filesystem type, (4) Image encryption/compression not supported"
                    }
                raise
            
            try:
                # Step 6: Collect artifacts
                artifacts = []
                
                # Filesystem artifacts
                log.info(f"Scanning filesystem (max {max_files} files)...")
                file_count = 0
                try:
                    for file_info in source.list_files("/", recursive=True, max_depth=5):
                        if file_count >= max_files:
                            log.warning(f"Reached maximum file limit ({max_files})")
                            break
                        
                        artifact = self._file_info_to_artifact(file_info, case_id)
                        if artifact:
                            artifacts.append(artifact)
                            file_count += 1
                            
                            if file_count % 100 == 0:
                                log.info(f"Progress: {file_count} files processed...")
                except Exception as e:
                    log.error(f"Error during filesystem scan: {e}")
                    # Continue with whatever artifacts we collected
                
                log.info(f"Filesystem scan complete: {len(artifacts)} artifacts")
                
                # If we got at least some artifacts, consider it a success
                if len(artifacts) == 0:
                    return {
                        "status": "error",
                        "error": "No artifacts extracted from forensic image. Image may be empty, encrypted, or have unsupported filesystem."
                    }
                
                # Browser artifacts - skip for now if filesystem had issues
                # if extract_browser:
                #     browser_artifacts = self._extract_browser_artifacts(source, case_id)
                #     artifacts.extend(browser_artifacts)
                #     log.info(f"Browser artifacts: {len(browser_artifacts)}")
                
                # EVTX artifacts - skip for now
                # if extract_evtx:
                #     evtx_artifacts = self._extract_evtx_artifacts(source, case_id)
                #     artifacts.extend(evtx_artifacts)
                #     log.info(f"EVTX artifacts: {len(evtx_artifacts)}")
                
                log.info(f"Total artifacts collected: {len(artifacts)}")
                
                return {
                    "status": "success",
                    "artifacts": artifacts,
                    "metadata": source.get_metadata(),
                    "total_artifacts": len(artifacts),
                }
                
            finally:
                source.close()
        
        except Exception as e:
            log.exception(f"Failed to collect from forensic image: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def _file_info_to_artifact(self, file_info: Dict, case_id: str) -> Optional[Dict]:
        """Convert filesystem file_info to SPECTRA artifact format"""
        # Skip directories
        if file_info.get("is_directory"):
            return None
        
        # Skip deleted files for now
        if file_info.get("is_deleted"):
            return None
        
        # Build artifact
        ext = Path(file_info["name"]).suffix.lower()
        
        # Apply existing rule-based scoring
        from evidence_collector import RULE_OVERRIDES, RISKY_EXTENSIONS, SAFE_EXTENSIONS
        
        rule_score = 0
        name_lower = file_info["name"].lower()
        for pattern, score in RULE_OVERRIDES.items():
            if pattern.lower() in name_lower:
                rule_score = max(rule_score, score)
        
        is_risky = ext in RISKY_EXTENSIONS
        is_safe = ext in SAFE_EXTENSIONS
        
        artifact = {
            "type": "file",
            "path": file_info.get("evidence_path", file_info["name"]),
            "name": file_info["name"],
            "extension": ext,
            "size_bytes": file_info.get("size_bytes", 0),
            "created_at": file_info.get("created_at"),
            "modified_at": file_info.get("modified_at"),
            "accessed_at": file_info.get("accessed_at"),
            "rule_score": rule_score,
            "risk_flag": "high" if rule_score > 70 else ("medium" if is_risky else "low"),
            
            # Forensic metadata
            "source_type": "forensic_image",
            "source_case_id": case_id,
            "inode": file_info.get("inode"),
            
            # ML features
            "features": {
                "network_activity": 0.0,
                "session_time": 0.0,
                "data_transfer": min(file_info.get("size_bytes", 0) / 100_000_000, 1.0),
                "connection_status": 2 if rule_score > 80 else (1 if is_risky else 0),
            },
        }
        
        return artifact
    
    def _extract_browser_artifacts(self, source: ForensicImageSource, case_id: str) -> List[Dict]:
        """
        Extract browser history from forensic image.
        Searches for Chrome/Firefox history databases.
        """
        artifacts = []
        
        # Common browser history paths (Windows)
        browser_paths = [
            "Users/*/AppData/Local/Google/Chrome/User Data/Default/History",
            "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
        ]
        
        # TODO: Implement browser database extraction and parsing
        # This would require:
        # 1. Search for History/places.sqlite files in the image
        # 2. Extract them to temporary location
        # 3. Use existing BrowserHistoryParser
        # 4. Clean up temp files
        
        log.info("Browser artifact extraction not yet implemented for forensic images")
        return artifacts
    
    def _extract_evtx_artifacts(self, source: ForensicImageSource, case_id: str) -> List[Dict]:
        """
        Extract Windows event logs from forensic image.
        Searches for .evtx files.
        """
        artifacts = []
        
        # Common EVTX paths
        evtx_base = "Windows/System32/winevt/Logs"
        
        # TODO: Implement EVTX extraction and parsing
        # This would require:
        # 1. Search for *.evtx files in the image
        # 2. Extract them to temporary location
        # 3. Use existing EventLogParser
        # 4. Clean up temp files
        
        log.info("EVTX artifact extraction not yet implemented for forensic images")
        return artifacts


def main():
    """CLI entry point for testing"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        stream=sys.stderr
    )
    
    parser = argparse.ArgumentParser(description="SPECTRA Forensic Evidence Collector")
    parser.add_argument("--config-file", type=str, help="Path to JSON config file")
    parser.add_argument("--case-id", type=str, help="Case ID")
    parser.add_argument("--image-path", type=str, help="Path to forensic image (first segment)")
    parser.add_argument("--max-files", type=int, default=1000, help="Maximum files to process")
    parser.add_argument("--info-only", action="store_true", help="Only show image info, don't collect")
    
    args = parser.parse_args()
    
    collector = ForensicEvidenceCollector()
    
    if args.info_only and args.image_path:
        # Just show image info
        log.info(f"Analyzing forensic image: {args.image_path}")
        info = get_image_info(args.image_path)
        print(json.dumps(info, indent=2))
        return
    
    if args.config_file:
        # Read config from file
        with open(args.config_file, 'r') as f:
            config = json.load(f)
    elif args.image_path:
        # Build config from command line
        config = {
            "case_id": args.case_id or "TEST-CASE",
            "image_path": args.image_path,
            "max_files": args.max_files,
        }
    else:
        parser.print_help()
        return
    
    # Collect evidence
    result = collector.collect_from_image(config)
    
    # Output JSON to stdout
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
