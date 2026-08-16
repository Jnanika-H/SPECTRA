"""
Evidence Source Abstraction
============================
Provides a common interface for accessing evidence from different sources:
- Local filesystem directories (existing functionality)
- Forensic disk images (new functionality)

This abstraction allows the existing parsers to work with both sources
without modification.
"""

import os
import hashlib
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Generator, Dict, BinaryIO
from datetime import datetime, timezone

log = logging.getLogger("spectra.forensic.source")


class EvidenceSource(ABC):
    """
    Abstract base class for evidence sources.
    Provides a common interface for filesystem-like operations.
    """
    
    @abstractmethod
    def get_type(self) -> str:
        """Return the source type (e.g., 'local_directory', 'forensic_image')"""
        pass
    
    @abstractmethod
    def get_metadata(self) -> Dict:
        """Return source metadata"""
        pass
    
    @abstractmethod
    def list_files(self, path: str = "/", recursive: bool = False, max_depth: int = 10) -> Generator[Dict, None, None]:
        """
        List files at the given path.
        
        Args:
            path: Path to list
            recursive: Whether to recurse into subdirectories
            max_depth: Maximum recursion depth
            
        Yields:
            Dict with file metadata
        """
        pass
    
    @abstractmethod
    def read_file(self, path: str, max_size: Optional[int] = None) -> bytes:
        """
        Read file contents.
        
        Args:
            path: File path
            max_size: Maximum bytes to read (None for all)
            
        Returns:
            File contents as bytes
        """
        pass
    
    @abstractmethod
    def file_exists(self, path: str) -> bool:
        """Check if file exists"""
        pass
    
    @abstractmethod
    def get_file_hash(self, path: str) -> str:
        """Get SHA-256 hash of file"""
        pass
    
    @abstractmethod
    def close(self):
        """Clean up resources"""
        pass


class LocalDirectorySource(EvidenceSource):
    """
    Evidence source backed by a normal filesystem directory.
    This wraps the existing local filesystem functionality.
    """
    
    def __init__(self, root_path: str):
        """
        Initialize local directory source.
        
        Args:
            root_path: Path to the root directory
        """
        self.root_path = Path(root_path)
        if not self.root_path.exists():
            raise FileNotFoundError(f"Directory does not exist: {root_path}")
        
        self.source_type = "local_directory"
        log.info(f"Initialized local directory source: {root_path}")
    
    def get_type(self) -> str:
        return "SYSTEM_PATH"
    
    def get_metadata(self) -> Dict:
        return {
            "source_type": self.source_type,
            "root_path": str(self.root_path),
            "absolute_path": str(self.root_path.absolute()),
        }
    
    def list_files(self, path: str = "/", recursive: bool = False, max_depth: int = 10) -> Generator[Dict, None, None]:
        """List files in the local directory"""
        # Convert relative path to absolute
        if path == "/":
            search_path = self.root_path
        else:
            search_path = self.root_path / path.lstrip("/")
        
        if not search_path.exists():
            log.warning(f"Path does not exist: {search_path}")
            return
        
        if recursive:
            yield from self._walk_recursive(search_path, max_depth)
        else:
            yield from self._list_single_dir(search_path)
    
    def _list_single_dir(self, dirpath: Path) -> Generator[Dict, None, None]:
        """List files in a single directory"""
        try:
            for item in dirpath.iterdir():
                try:
                    stat = item.stat()
                    yield {
                        "name": item.name,
                        "path": str(item.relative_to(self.root_path)),
                        "absolute_path": str(item),
                        "size_bytes": stat.st_size if item.is_file() else 0,
                        "is_directory": item.is_dir(),
                        "is_deleted": False,
                        "created_at": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
                        "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                        "accessed_at": datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat(),
                    }
                except (PermissionError, OSError) as e:
                    log.debug(f"Skipping {item}: {e}")
        except (PermissionError, OSError) as e:
            log.warning(f"Cannot list directory {dirpath}: {e}")
    
    def _walk_recursive(self, root: Path, max_depth: int, current_depth: int = 0) -> Generator[Dict, None, None]:
        """Recursively walk directory tree"""
        if current_depth >= max_depth:
            return
        
        for item_dict in self._list_single_dir(root):
            yield item_dict
            
            if item_dict["is_directory"]:
                subdir = Path(item_dict["absolute_path"])
                yield from self._walk_recursive(subdir, max_depth, current_depth + 1)
    
    def read_file(self, path: str, max_size: Optional[int] = None) -> bytes:
        """Read file from local filesystem"""
        file_path = self.root_path / path.lstrip("/")
        
        try:
            with open(file_path, 'rb') as f:
                if max_size:
                    return f.read(max_size)
                return f.read()
        except Exception as e:
            log.error(f"Cannot read file {file_path}: {e}")
            raise
    
    def file_exists(self, path: str) -> bool:
        """Check if file exists"""
        file_path = self.root_path / path.lstrip("/")
        return file_path.exists() and file_path.is_file()
    
    def get_file_hash(self, path: str) -> str:
        """Calculate SHA-256 hash of file"""
        file_path = self.root_path / path.lstrip("/")
        
        h = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            log.error(f"Cannot hash file {file_path}: {e}")
            return ""
    
    def close(self):
        """No cleanup needed for local directory"""
        pass


class ForensicImageSource(EvidenceSource):
    """
    Evidence source backed by a forensic disk image (E01/EWF, RAW/DD).
    Provides read-only access to the filesystem inside the image.
    """
    
    def __init__(self, case_id: str, image_path: str, image_format: str, segments: list):
        """
        Initialize forensic image source.
        
        Args:
            case_id: Case identifier
            image_path: Path to first segment
            image_format: Image format (E01/EWF, RAW/DD)
            segments: List of all segment paths
        """
        from .image_reader import ForensicImageReader, ImageHandle
        from .filesystem_reader import FilesystemReader, detect_partitions
        
        self.case_id = case_id
        self.image_path = image_path
        self.image_format = image_format
        self.segments = segments
        self.source_type = "forensic_image"
        
        # Initialize image reader
        self.image_reader = ForensicImageReader(image_path, image_format)
        if not self.image_reader.open(segments):
            raise IOError(f"Failed to open forensic image: {image_path}")
        
        # Detect partitions
        self.partitions = detect_partitions(self.image_reader)
        
        # Open filesystem on first valid partition
        self.fs_reader = FilesystemReader(self.image_reader)
        
        # Try each partition until we find one that works
        opened = False
        for partition in self.partitions:
            # Skip metadata/unallocated partitions
            if "Primary Table" in partition.get("description", ""):
                continue
                
            offset = partition["start_offset"]
            log.info(f"Trying partition at offset {offset}: {partition.get('description', 'Unknown')}")
            
            if self.fs_reader.open(offset):
                opened = True
                log.info(f"Successfully opened filesystem at offset {offset}")
                break
        
        if not opened:
            raise IOError("Failed to open filesystem in forensic image")
        
        log.info(f"Initialized forensic image source: {case_id}")
        log.info(f"  Format: {image_format}")
        log.info(f"  Filesystem: {self.fs_reader.fs_type}")
        log.info(f"  Partitions: {len(self.partitions)}")
    
    def get_type(self) -> str:
        return "FORENSIC_IMAGE"
    
    def get_metadata(self) -> Dict:
        return {
            "source_type": self.source_type,
            "case_id": self.case_id,
            "image_path": self.image_path,
            "image_format": self.image_format,
            "filesystem_type": self.fs_reader.fs_type,
            "segment_count": len(self.segments),
            "segments": self.segments,
            "partition_count": len(self.partitions),
            "partitions": self.partitions,
            "image_size_bytes": self.image_reader.get_size(),
            "image_size_gb": round(self.image_reader.get_size() / (1024**3), 2),
        }
    
    def list_files(self, path: str = "/", recursive: bool = False, max_depth: int = 10) -> Generator[Dict, None, None]:
        """List files from forensic image filesystem"""
        try:
            if recursive:
                for file_info in self.fs_reader.walk(path, max_depth):
                    # Add source context
                    file_info["source_case_id"] = self.case_id
                    file_info["source_type"] = "forensic_image"
                    file_info["evidence_path"] = f"{path.rstrip('/')}/{file_info['name']}"
                    yield file_info
            else:
                for file_info in self.fs_reader.list_directory(path):
                    file_info["source_case_id"] = self.case_id
                    file_info["source_type"] = "forensic_image"
                    file_info["evidence_path"] = f"{path.rstrip('/')}/{file_info['name']}"
                    yield file_info
        except Exception as e:
            log.error(f"Cannot list files from forensic image: {e}")
    
    def read_file(self, path: str, max_size: Optional[int] = None) -> bytes:
        """Read file from forensic image"""
        try:
            data = self.fs_reader.read_file(path)
            if max_size:
                return data[:max_size]
            return data
        except Exception as e:
            log.error(f"Cannot read file from forensic image: {e}")
            raise
    
    def file_exists(self, path: str) -> bool:
        """Check if file exists in forensic image"""
        return self.fs_reader.file_exists(path)
    
    def get_file_hash(self, path: str) -> str:
        """Calculate SHA-256 hash of file in forensic image"""
        try:
            data = self.read_file(path)
            return hashlib.sha256(data).hexdigest()
        except Exception as e:
            log.error(f"Cannot hash file from forensic image: {e}")
            return ""
    
    def close(self):
        """Close forensic image"""
        if self.image_reader:
            self.image_reader.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test local directory source
    print("\n=== Testing LocalDirectorySource ===")
    try:
        source = LocalDirectorySource(".")
        print(f"Source type: {source.get_type()}")
        print(f"Metadata: {source.get_metadata()}")
        
        print("\nListing files:")
        count = 0
        for file_info in source.list_files(".", recursive=False):
            print(f"  - {file_info['name']} ({file_info['size_bytes']} bytes)")
            count += 1
            if count >= 5:
                break
        
        source.close()
        print("✓ LocalDirectorySource works")
    except Exception as e:
        print(f"✗ LocalDirectorySource failed: {e}")
