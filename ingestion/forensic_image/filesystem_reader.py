"""
Filesystem Reader
=================
Parses filesystems inside forensic images.
Currently focuses on NTFS support using pytsk3.
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Generator
from pathlib import Path

log = logging.getLogger("spectra.forensic.filesystem")

# Check if pytsk3 is available
PYTSK3_AVAILABLE = False
try:
    import pytsk3
    PYTSK3_AVAILABLE = True
    log.info("pytsk3 library loaded successfully")
except ImportError:
    log.warning("pytsk3 not available - filesystem parsing will be limited")
    log.warning("Install with: pip install pytsk3")


class FilesystemType:
    """Supported filesystem types"""
    NTFS = "NTFS"
    FAT32 = "FAT32"
    EXT4 = "EXT4"
    HFS_PLUS = "HFS+"
    UNKNOWN = "UNKNOWN"


class FilesystemReader:
    """
    Read filesystem structures from forensic images.
    Provides read-only access to files and directories.
    """
    
    def __init__(self, image_handle):
        """
        Initialize filesystem reader.
        
        Args:
            image_handle: ForensicImageReader or file-like object
        """
        self.image_handle = image_handle
        self.img_info = None
        self.fs_info = None
        self.fs_type = FilesystemType.UNKNOWN
        self._root_inum = None
    
    def open(self, offset: int = 0) -> bool:
        """
        Open the filesystem at the specified offset.
        
        Args:
            offset: Byte offset of the partition (0 for whole disk)
            
        Returns:
            True if successful
        """
        if not PYTSK3_AVAILABLE:
            log.error("Cannot parse filesystem: pytsk3 not available")
            return False
        
        try:
            # Create TSK image info wrapper
            self.img_info = Img_Info(self.image_handle)
            
            # Open filesystem at offset
            self.fs_info = pytsk3.FS_Info(self.img_info, offset=offset)
            
            # Detect filesystem type
            fs_type_int = self.fs_info.info.ftype
            self.fs_type = self._detect_fs_type(fs_type_int)
            
            # Get root inode number
            self._root_inum = self.fs_info.info.root_inum
            
            log.info(f"Opened filesystem: {self.fs_type} at offset {offset}")
            return True
            
        except Exception as e:
            log.error(f"Failed to open filesystem: {e}")
            return False
    
    def _detect_fs_type(self, fs_type_int: int) -> str:
        """Detect filesystem type from TSK constant"""
        if not PYTSK3_AVAILABLE:
            return FilesystemType.UNKNOWN
        
        # Map pytsk3 constants to our types
        fs_map = {
            pytsk3.TSK_FS_TYPE_NTFS: FilesystemType.NTFS,
            pytsk3.TSK_FS_TYPE_FAT32: FilesystemType.FAT32,
            pytsk3.TSK_FS_TYPE_EXT4: FilesystemType.EXT4,
            pytsk3.TSK_FS_TYPE_HFS: FilesystemType.HFS_PLUS,
        }
        
        return fs_map.get(fs_type_int, FilesystemType.UNKNOWN)
    
    def list_directory(self, path: str = "/") -> Generator[Dict, None, None]:
        """
        List files and directories at the given path.
        
        Args:
            path: Path to list (Unix-style, e.g., "/Users/Admin/Downloads")
            
        Yields:
            Dict with file metadata
        """
        if not self.fs_info:
            log.error("Filesystem not opened")
            return
        
        try:
            # Convert path to inode
            if path == "/":
                directory = self.fs_info.open_dir(inode=self._root_inum)
            else:
                # Remove leading slash for TSK
                clean_path = path.lstrip("/")
                directory = self.fs_info.open_dir(path=clean_path)
            
            for entry in directory:
                # Skip "." and ".." and unallocated entries
                if entry.info.name.name in [b".", b".."]:
                    continue
                
                try:
                    file_info = self._get_file_info(entry)
                    if file_info:
                        yield file_info
                except Exception as e:
                    log.debug(f"Could not read entry: {e}")
                    continue
                    
        except Exception as e:
            log.error(f"Could not list directory {path}: {e}")
    
    def walk(self, path: str = "/", max_depth: int = 10, current_depth: int = 0) -> Generator[Dict, None, None]:
        """
        Recursively walk the filesystem tree.
        
        Args:
            path: Starting path
            max_depth: Maximum recursion depth
            current_depth: Current depth (internal)
            
        Yields:
            Dict with file metadata
        """
        if current_depth >= max_depth:
            return
        
        for item in self.list_directory(path):
            yield item
            
            # Recurse into directories
            if item.get("is_directory") and not item.get("is_deleted"):
                subdir_path = os.path.join(path, item["name"]).replace("\\", "/")
                yield from self.walk(subdir_path, max_depth, current_depth + 1)
    
    def _get_file_info(self, entry) -> Optional[Dict]:
        """Extract metadata from a filesystem entry"""
        try:
            name = entry.info.name.name.decode('utf-8', errors='replace')
            
            # Get file metadata
            meta = entry.info.meta
            if meta is None:
                return None
            
            is_directory = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
            is_deleted = entry.info.name.flags == pytsk3.TSK_FS_NAME_FLAG_UNALLOC
            
            # Get timestamps
            created = self._timestamp_to_iso(meta.crtime) if hasattr(meta, 'crtime') else None
            modified = self._timestamp_to_iso(meta.mtime) if hasattr(meta, 'mtime') else None
            accessed = self._timestamp_to_iso(meta.atime) if hasattr(meta, 'atime') else None
            changed = self._timestamp_to_iso(meta.ctime) if hasattr(meta, 'ctime') else None
            
            return {
                "name": name,
                "size_bytes": meta.size,
                "is_directory": is_directory,
                "is_deleted": is_deleted,
                "inode": entry.info.meta.addr,
                "created_at": created,
                "modified_at": modified,
                "accessed_at": accessed,
                "changed_at": changed,
            }
            
        except Exception as e:
            log.debug(f"Could not extract file info: {e}")
            return None
    
    def read_file(self, path: str) -> bytes:
        """
        Read the contents of a file.
        
        Args:
            path: Path to the file
            
        Returns:
            File contents as bytes
        """
        if not self.fs_info:
            raise IOError("Filesystem not opened")
        
        try:
            clean_path = path.lstrip("/")
            file_obj = self.fs_info.open(clean_path)
            
            # Read file in chunks to avoid memory issues
            chunks = []
            offset = 0
            chunk_size = 1024 * 1024  # 1MB chunks
            
            while offset < file_obj.info.meta.size:
                data = file_obj.read_random(offset, chunk_size)
                if not data:
                    break
                chunks.append(data)
                offset += len(data)
            
            return b''.join(chunks)
            
        except Exception as e:
            log.error(f"Could not read file {path}: {e}")
            raise
    
    def file_exists(self, path: str) -> bool:
        """Check if a file exists at the given path"""
        try:
            clean_path = path.lstrip("/")
            self.fs_info.open(clean_path)
            return True
        except:
            return False
    
    @staticmethod
    def _timestamp_to_iso(timestamp: int) -> Optional[str]:
        """Convert Unix timestamp to ISO format"""
        if timestamp == 0:
            return None
        try:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            return dt.isoformat()
        except (ValueError, OSError):
            return None


class Img_Info(pytsk3.Img_Info if PYTSK3_AVAILABLE else object):
    """
    TSK Img_Info implementation that wraps a ForensicImageReader
    to provide a file-like interface for pytsk3.
    """
    
    def __init__(self, image_handle):
        self._handle = image_handle
        if PYTSK3_AVAILABLE:
            # Initialize parent if pytsk3 is available
            pytsk3.Img_Info.__init__(self, url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
    
    def close(self):
        pass
    
    def read(self, offset: int, size: int) -> bytes:
        """Read from the image at the specified offset"""
        return self._handle.read(size, offset=offset)
    
    def get_size(self) -> int:
        """Get the size of the image"""
        if hasattr(self._handle, 'get_size'):
            return self._handle.get_size()
        # For file objects
        current_pos = self._handle.tell()
        self._handle.seek(0, 2)  # Seek to end
        size = self._handle.tell()
        self._handle.seek(current_pos)
        return size


def detect_partitions(image_handle) -> List[Dict]:
    """
    Detect partitions in a disk image.
    
    Args:
        image_handle: ForensicImageReader or file-like object
        
    Returns:
        List of partition information dicts
    """
    if not PYTSK3_AVAILABLE:
        log.error("Cannot detect partitions: pytsk3 not available")
        return []
    
    partitions = []
    
    try:
        img_info = Img_Info(image_handle)
        volume = pytsk3.Volume_Info(img_info)
        
        for partition in volume:
            # Skip unallocated and metadata partitions
            if partition.flags == pytsk3.TSK_VS_PART_FLAG_UNALLOC:
                continue
            
            part_info = {
                "index": partition.addr,
                "description": partition.desc.decode('utf-8', errors='replace'),
                "start_offset": partition.start * 512,  # Convert sectors to bytes
                "length_bytes": partition.len * 512,
                "length_gb": (partition.len * 512) / (1024**3),
            }
            
            partitions.append(part_info)
            log.info(f"Found partition {partition.addr}: {part_info['description']} "
                    f"({part_info['length_gb']:.2f} GB)")
        
    except Exception as e:
        log.warning(f"Could not detect partitions: {e}")
        # If no partition table, assume whole disk is one partition
        partitions = [{
            "index": 0,
            "description": "Whole Disk",
            "start_offset": 0,
            "length_bytes": image_handle.get_size() if hasattr(image_handle, 'get_size') else 0,
            "length_gb": 0,
        }]
    
    return partitions


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    if PYTSK3_AVAILABLE:
        print("✓ pytsk3 is available")
    else:
        print("✗ pytsk3 is not available")
        print("  Install with: pip install pytsk3")
