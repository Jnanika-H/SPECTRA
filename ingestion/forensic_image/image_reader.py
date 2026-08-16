"""
Forensic Image Reader
=====================
Provides read-only access to forensic disk images using libewf (pyewf).
Supports E01/EWF format and provides a file-like interface.
"""

import os
import logging
from typing import Optional, BinaryIO
from pathlib import Path

log = logging.getLogger("spectra.forensic.reader")

# Check if pyewf is available
PYEWF_AVAILABLE = False
try:
    import pyewf
    PYEWF_AVAILABLE = True
    log.info("pyewf library loaded successfully")
except ImportError:
    log.warning("pyewf not available - E01/EWF support will be limited")
    log.warning("Install with: pip install pyewf or libewf-python")


class ForensicImageReader:
    """
    Read-only interface to forensic disk images.
    Supports E01/EWF and RAW/DD formats.
    """
    
    def __init__(self, image_path: str, image_format: str):
        """
        Initialize forensic image reader.
        
        Args:
            image_path: Path to first segment of the image
            image_format: Format string from image_detector
        """
        self.image_path = image_path
        self.image_format = image_format
        self.handle = None
        self._is_open = False
        self._size = 0
        
    def open(self, segments: list[str]) -> bool:
        """
        Open the forensic image for reading.
        
        Args:
            segments: List of all segment paths in order
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if self.image_format == "E01/EWF":
                return self._open_ewf(segments)
            elif self.image_format == "RAW/DD":
                return self._open_raw(segments[0])
            else:
                log.error(f"Unsupported image format: {self.image_format}")
                return False
        except Exception as e:
            log.error(f"Failed to open forensic image: {e}")
            return False
    
    def _open_ewf(self, segments: list[str]) -> bool:
        """Open E01/EWF image using pyewf"""
        if not PYEWF_AVAILABLE:
            log.error("Cannot open E01/EWF image: pyewf library not available")
            log.error("Please install: pip install pyewf")
            return False
        
        try:
            # Create EWF handle
            self.handle = pyewf.handle()
            
            # Open with all segments
            # pyewf expects a list of filenames
            filenames = [str(seg) for seg in segments]
            self.handle.open(filenames)
            
            # Get media size
            self._size = self.handle.get_media_size()
            self._is_open = True
            
            log.info(f"Opened E01/EWF image: {self.image_path}")
            log.info(f"Media size: {self._size / (1024**3):.2f} GB")
            log.info(f"Segments: {len(segments)}")
            
            return True
            
        except Exception as e:
            log.error(f"Failed to open E01/EWF image: {e}")
            return False
    
    def _open_raw(self, image_path: str) -> bool:
        """Open RAW/DD image"""
        try:
            self.handle = open(image_path, 'rb')
            self._size = Path(image_path).stat().st_size
            self._is_open = True
            
            log.info(f"Opened RAW/DD image: {image_path}")
            log.info(f"Image size: {self._size / (1024**3):.2f} GB")
            
            return True
            
        except Exception as e:
            log.error(f"Failed to open RAW/DD image: {e}")
            return False
    
    def read(self, size: int = -1, offset: Optional[int] = None) -> bytes:
        """
        Read bytes from the image.
        
        Args:
            size: Number of bytes to read (-1 for all remaining)
            offset: Optional absolute offset to seek to first
            
        Returns:
            Bytes read from the image
        """
        if not self._is_open or self.handle is None:
            raise IOError("Image not opened")
        
        try:
            if offset is not None:
                self.seek(offset)
            
            if self.image_format == "E01/EWF":
                if size == -1:
                    size = self._size - self.tell()
                return self.handle.read(size)
            else:  # RAW/DD
                return self.handle.read(size)
                
        except Exception as e:
            log.error(f"Read error: {e}")
            return b''
    
    def seek(self, offset: int, whence: int = 0) -> int:
        """
        Seek to a position in the image.
        
        Args:
            offset: Offset in bytes
            whence: 0=absolute, 1=relative, 2=from end
            
        Returns:
            New absolute position
        """
        if not self._is_open or self.handle is None:
            raise IOError("Image not opened")
        
        if self.image_format == "E01/EWF":
            return self.handle.seek(offset, whence)
        else:
            return self.handle.seek(offset, whence)
    
    def tell(self) -> int:
        """Get current position in the image"""
        if not self._is_open or self.handle is None:
            return 0
        
        if self.image_format == "E01/EWF":
            return self.handle.get_offset()
        else:
            return self.handle.tell()
    
    def get_size(self) -> int:
        """Get total size of the image in bytes"""
        return self._size
    
    def close(self):
        """Close the image"""
        if self._is_open and self.handle is not None:
            try:
                self.handle.close()
                log.info(f"Closed forensic image: {self.image_path}")
            except Exception as e:
                log.warning(f"Error closing image: {e}")
            finally:
                self._is_open = False
                self.handle = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def is_open(self) -> bool:
        """Check if the image is currently open"""
        return self._is_open


class ImageHandle:
    """
    File-like wrapper around ForensicImageReader for compatibility
    with filesystem parsers that expect file-like objects.
    """
    
    def __init__(self, reader: ForensicImageReader):
        self.reader = reader
    
    def read(self, size: int = -1) -> bytes:
        return self.reader.read(size)
    
    def seek(self, offset: int, whence: int = 0) -> int:
        return self.reader.seek(offset, whence)
    
    def tell(self) -> int:
        return self.reader.tell()
    
    def close(self):
        pass  # Don't close the underlying reader
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test if pyewf is available
    if PYEWF_AVAILABLE:
        print("✓ pyewf is available")
        print(f"  Version: {pyewf.get_version()}")
    else:
        print("✗ pyewf is not available")
        print("  Install with: pip install libewf-python")
