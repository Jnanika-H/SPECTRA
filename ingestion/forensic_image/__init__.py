"""
SPECTRA Forensic Image Ingestion Module
=========================================
Provides read-only access to forensic disk images (E01/EWF, RAW/DD)
and extracts artifacts through a common interface compatible with
the existing SPECTRA analysis pipeline.
"""

from .image_detector import detect_image_format, find_image_segments
from .image_reader import ForensicImageReader
from .filesystem_reader import FilesystemReader
from .evidence_source import EvidenceSource, LocalDirectorySource, ForensicImageSource

__all__ = [
    'detect_image_format',
    'find_image_segments',
    'ForensicImageReader',
    'FilesystemReader',
    'EvidenceSource',
    'LocalDirectorySource',
    'ForensicImageSource',
]
