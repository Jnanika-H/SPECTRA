"""
Forensic Image Format Detection
================================
Detects forensic image formats (E01/EWF, RAW/DD) and locates all segments
for split images.
"""

import os
import struct
import logging
from pathlib import Path
from typing import Optional, List, Tuple

log = logging.getLogger("spectra.forensic.detector")


class ImageFormat:
    """Supported forensic image formats"""
    E01_EWF = "E01/EWF"
    RAW_DD = "RAW/DD"
    UNKNOWN = "UNKNOWN"


def detect_image_format(image_path: str) -> str:
    """
    Detect the format of a forensic image file.
    
    Args:
        image_path: Path to the image file
        
    Returns:
        ImageFormat constant (E01_EWF, RAW_DD, or UNKNOWN)
    """
    path = Path(image_path)
    
    if not path.exists():
        log.error(f"Image file does not exist: {image_path}")
        return ImageFormat.UNKNOWN
    
    # Check file extension first
    ext = path.suffix.lower()
    
    # E01/EWF images typically have .e01, .e02, etc. or .ex01 extensions
    if ext in ['.e01', '.ex01'] or (ext.startswith('.e') and ext[2:].isdigit()):
        # Verify EWF magic bytes
        if _verify_ewf_signature(path):
            return ImageFormat.E01_EWF
    
    # Check for RAW/DD by file extension or lack thereof
    if ext in ['.dd', '.raw', '.img', '']:
        return ImageFormat.RAW_DD
    
    # Try to detect by signature
    try:
        with open(path, 'rb') as f:
            signature = f.read(16)
            
        # EWF signature: "EVF" or "LVF" at various offsets
        if b'EVF' in signature or b'LVF' in signature or signature.startswith(b'EVF') or signature.startswith(b'LVF'):
            return ImageFormat.E01_EWF
            
    except Exception as e:
        log.warning(f"Could not read signature from {image_path}: {e}")
    
    return ImageFormat.UNKNOWN


def _verify_ewf_signature(path: Path) -> bool:
    """
    Verify EWF file signature.
    EWF files start with specific signatures.
    """
    try:
        with open(path, 'rb') as f:
            # Read first 16 bytes
            header = f.read(16)
            
            # EWF version 1: starts with "EVF" + 0x09/0x0d/0x0a + "EVF"
            # EWF version 2: starts with "LVF"
            if header.startswith(b'EVF') or header.startswith(b'LVF'):
                return True
                
            # Also check for encase signatures
            if b'EVF' in header[:8] or b'LVF' in header[:8]:
                return True
                
    except Exception as e:
        log.debug(f"Could not verify EWF signature for {path}: {e}")
    
    return False


def find_image_segments(image_path: str) -> List[str]:
    """
    Find all segments of a split forensic image.
    
    For example, if given "CASE.E01", will find:
    - CASE.E01
    - CASE.E02
    - CASE.E03
    - ...
    
    Args:
        image_path: Path to the first segment or any segment
        
    Returns:
        List of all segment paths in order
    """
    path = Path(image_path)
    
    if not path.exists():
        log.error(f"Image file does not exist: {image_path}")
        return []
    
    directory = path.parent
    stem = path.stem
    ext = path.suffix.lower()
    
    segments = []
    
    # Handle E01/EWF split images
    if ext.startswith('.e') and len(ext) == 4 and ext[2:].isdigit():
        # Extract base name (everything before .E01)
        base_name = stem
        
        # Find all segments: .E01, .E02, .E03, etc.
        # NO HARD-CODED LIMIT - search until no more found
        for i in range(1, 10000):  # Support up to 9999 segments
            segment_ext = f'.E{i:02d}'
            segment_path = directory / f"{base_name}{segment_ext}"
            
            if segment_path.exists():
                segments.append(str(segment_path))
            else:
                # Stop when we can't find the next segment
                break
    
    # Handle ex01 format (EnCase v7+)
    elif ext == '.ex01' or (ext.startswith('.ex') and ext[3:].isdigit()):
        base_name = stem
        
        for i in range(1, 10000):
            segment_ext = f'.Ex{i:02d}'
            segment_path = directory / f"{base_name}{segment_ext}"
            
            if segment_path.exists():
                segments.append(str(segment_path))
            else:
                break
    
    # For RAW/DD or single-file images, return just the one file
    elif ext in ['.dd', '.raw', '.img', '.001']:
        segments = [str(path)]
    
    else:
        # Unknown format or single file
        segments = [str(path)]
    
    if len(segments) > 1:
        log.info(f"Found {len(segments)} segments for split image: {path.name}")
    elif len(segments) == 1:
        log.info(f"Single segment image: {path.name}")
    
    return segments if segments else [str(path)]


def validate_segments(segments: List[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate that all required segments are present and accessible.
    
    Args:
        segments: List of segment paths
        
    Returns:
        (is_valid, error_message)
    """
    if not segments:
        return False, "No image segments provided"
    
    for i, segment_path in enumerate(segments, start=1):
        path = Path(segment_path)
        
        if not path.exists():
            return False, f"Missing segment {i}: {segment_path}"
        
        if not path.is_file():
            return False, f"Segment {i} is not a file: {segment_path}"
        
        if not os.access(path, os.R_OK):
            return False, f"Segment {i} is not readable: {segment_path}"
    
    return True, None


def get_image_info(image_path: str) -> dict:
    """
    Get basic information about a forensic image.
    
    Returns:
        dict with keys: format, segments, total_size, first_segment
    """
    segments = find_image_segments(image_path)
    image_format = detect_image_format(image_path)
    
    total_size = 0
    for seg in segments:
        try:
            total_size += Path(seg).stat().st_size
        except Exception:
            pass
    
    is_valid, error = validate_segments(segments)
    
    return {
        "format": image_format,
        "segments": segments,
        "segment_count": len(segments),
        "total_size_bytes": total_size,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
        "total_size_gb": round(total_size / (1024 * 1024 * 1024), 2),
        "first_segment": segments[0] if segments else None,
        "is_valid": is_valid,
        "error": error,
    }


def check_ewf_completeness(segments: List[str]) -> Tuple[bool, Optional[str]]:
    """
    Check if an EWF image is complete by attempting to open it with pyewf.
    
    Args:
        segments: List of segment file paths
        
    Returns:
        (is_complete, error_message)
        - is_complete: True if image can be opened and read successfully
        - error_message: Description of what's missing if incomplete
    """
    try:
        import pyewf
    except ImportError:
        return False, "pyewf library not available"
    
    try:
        # Try to open the EWF image
        handle = pyewf.handle()
        filenames = [str(seg) for seg in segments]
        handle.open(filenames)
        
        # Try to get media size - this will fail if segments are missing
        try:
            media_size = handle.get_media_size()
            log.info(f"EWF image reports media size: {media_size / (1024**3):.2f} GB")
            
            # Try to read from different offsets to verify completeness
            # If segments are missing, pyewf will error on certain reads
            try:
                # Read from beginning
                handle.seek(0)
                handle.read(512)
                
                # Try reading from near the end
                if media_size > 1024:
                    test_offset = media_size - 1024
                    handle.seek(test_offset)
                    data = handle.read(512)
                    
                    if not data or len(data) == 0:
                        handle.close()
                        return False, f"Cannot read data at offset {test_offset} - additional segments may be required"
                
                handle.close()
                return True, None
                
            except Exception as read_error:
                handle.close()
                error_str = str(read_error)
                
                # Check if error indicates missing segments
                if "missing segment" in error_str.lower():
                    # Try to extract which segment is missing
                    return False, "EWF image requires additional segments to be complete"
                
                # Some other read error
                return False, f"Cannot verify image completeness: {error_str}"
                
        except Exception as size_error:
            handle.close()
            return False, f"Cannot read EWF metadata: {str(size_error)}"
            
    except Exception as e:
        error_str = str(e)
        if "missing segment" in error_str.lower() or "unable to open" in error_str.lower():
            return False, "Cannot open EWF image - may require additional segments"
        return False, f"EWF validation error: {error_str}"


if __name__ == "__main__":
    # Test with example paths
    logging.basicConfig(level=logging.INFO)
    
    test_paths = [
        "D:\\Evidence\\CASE-2026-001\\CASE.E01",
        "C:\\Forensics\\disk.dd",
        "/mnt/evidence/image.E01",
    ]
    
    for test_path in test_paths:
        print(f"\n Testing: {test_path}")
        info = get_image_info(test_path)
        print(f"Format: {info['format']}")
        print(f"Segments: {info['segment_count']}")
        print(f"Size: {info['total_size_gb']} GB")
        print(f"Valid: {info['is_valid']}")
        if info['error']:
            print(f"Error: {info['error']}")
