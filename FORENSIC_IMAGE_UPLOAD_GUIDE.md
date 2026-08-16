# SPECTRA Forensic Image Upload Implementation Guide

## Overview

This implementation adds **real forensic disk image ingestion** through a browser-based file picker interface while preserving all existing SPECTRA functionality.

## What Changed

### ✅ Frontend Changes

#### 1. IngestPanel.js
- **Removed:** Text input field for manual path entry
- **Added:** Native file picker with Browse button
- **Added:** Multi-file selection for split E01 segments
- **Added:** Client-side validation for segment matching
- **Added:** Visual display of selected files with size information
- **Added:** Format detection (E01/EWF, RAW/DD)

#### 2. api.js
- **Added:** `uploadForensicEvidence()` function
- **Added:** Progress tracking for large file uploads
- **Added:** Multipart form data support
- **Added:** 10-minute timeout for large files

### ✅ Backend Changes

#### 1. New Services
- **EvidenceStorageService.java**
  - Manages controlled evidence storage
  - Creates `evidence-storage/<case-id>/` directories
  - Handles large file streaming (no memory issues)
  - Calculates SHA-256 hashes
  - Validates file integrity

#### 2. New Controllers
- **EvidenceUploadController.java**
  - `POST /api/evidence/upload` - Upload forensic images
  - `POST /api/evidence/validate` - Pre-upload validation
  - Integrates with existing EvidenceService

#### 3. Configuration
- **application.yml**
  - Max file size: 10 GB per file
  - Max request size: 50 GB total
  - Chunked upload support

### ✅ Existing Features Preserved

- ✅ Demo Data mode works exactly as before
- ✅ System Paths mode unchanged
- ✅ All existing parsers (EVTX, Browser, PCAP, Filesystem) work
- ✅ AI analysis pipeline unchanged
- ✅ Timeline generation unchanged
- ✅ Report generation unchanged
- ✅ Blockchain verification unchanged

## User Workflow

### Before (Old Way - REMOVED)
```
User types: D:\Evidence\CASE-2026-001\CASE.E01
```

### After (New Way)
```
1. Click "Browse for Evidence" button
2. Windows File Picker opens
3. Navigate to evidence folder
4. Select CASE.E01 (or multiple segments)
5. Click "Validate Evidence" (optional)
6. Click "Ingest into CASE-XXX"
7. Files uploaded to secure storage
8. Forensic collector processes image
9. Artifacts stored in MongoDB
10. Ready for analysis
```

## Split Image Support

### Example: 3-segment E01 image
```
Evidence folder:
├── CASE.E01 (1.5 GB)
├── CASE.E02 (1.5 GB)
└── CASE.E03 (800 MB)

User selects ALL THREE files in file picker
↓
Frontend validates they belong together
↓
All segments uploaded to:
  evidence-storage/CASE-2026-001/
    ├── CASE.E01
    ├── CASE.E02
    └── CASE.E03
↓
Python forensic collector processes first segment
(pyewf automatically finds other segments in same directory)
```

## Technical Details

### File Upload Flow

```
Browser File Picker
        ↓
User selects files
        ↓
FormData with multipart/form-data
        ↓
POST /api/evidence/upload
        ↓
EvidenceUploadController
        ↓
EvidenceStorageService
        ↓
Stream to evidence-storage/<case-id>/
        ↓
Calculate SHA-256
        ↓
Call EvidenceService.ingest()
        ↓
Execute forensic_evidence_collector.py
        ↓
Process E01 → Filesystem → Artifacts
        ↓
Store in MongoDB
        ↓
Return success
```

### Security Measures

1. **Filename Sanitization**
   - Removes path traversal characters
   - Prevents directory escaping
   - Safe filename generation

2. **Controlled Storage**
   - Evidence stored in `evidence-storage/` only
   - Case-specific subdirectories
   - Read-only access from Python collectors

3. **Size Limits**
   - Per-file: 10 GB (configurable)
   - Per-request: 50 GB (configurable)
   - Prevents memory exhaustion

4. **Integrity Verification**
   - SHA-256 hash calculated on storage
   - Hash stored in MongoDB Evidence model
   - Tamper detection capability

### Browser Security Compliance

- ✅ Never exposes real local filesystem paths
- ✅ Uses File API properly
- ✅ No path string manipulation
- ✅ No directory access attempts
- ✅ Multipart upload standard

## Evidence Storage Structure

```
<project-root>/
├── evidence-storage/
│   ├── CASE-2026-001/
│   │   ├── CASE.E01
│   │   ├── CASE.E02
│   │   └── CASE.E03
│   ├── CASE-2026-002/
│   │   └── disk.dd
│   └── CASE-2026-003/
│       └── image.E01
├── backend/
├── frontend/
├── ai-engine/
└── ingestion/
```

## MongoDB Evidence Model

### New Fields Added
```java
private String evidenceSourceType;     // "FORENSIC_IMAGE" or "SYSTEM_PATH"
private String forensicImagePath;      // Path to first segment
private String forensicImageFormat;    // "E01/EWF" or "RAW/DD"
private Integer forensicSegmentCount;  // Number of segments
private String forensicFilesystemType; // "NTFS", "FAT32", etc.
private Long forensicInode;            // Inode from forensic image
```

## Testing

### Test Case 1: Single RAW Image
```
1. Navigate to Forensic Image tab
2. Click Browse
3. Select: test-disk.dd
4. Click Validate Evidence
5. Click Ingest
6. Verify upload progress shown
7. Verify artifacts appear in Evidence table
```

### Test Case 2: Split E01 Image
```
1. Navigate to Forensic Image tab
2. Click Browse
3. Select: CASE.E01, CASE.E02, CASE.E03
4. Verify format detected as "E01/EWF"
5. Verify segment count = 3
6. Click Validate Evidence
7. Verify validation passes
8. Click Ingest
9. Verify all segments uploaded
10. Verify artifacts extracted
```

### Test Case 3: Invalid Segments
```
1. Select: IMAGE1.E01, IMAGE2.E01 (different images)
2. Click Validate Evidence
3. Verify error: "segments don't match"
4. Cannot proceed with ingest
```

### Test Case 4: Existing System Paths Still Work
```
1. Navigate to System Paths tab
2. Enter: C:\Users\Test\Documents
3. Click Ingest
4. Verify existing functionality unchanged
```

## Dependencies

### Python (Already Installed)
```
pyewf       - E01/EWF format support
pytsk3      - Filesystem parsing
```

### Java (No New Dependencies)
- Spring Boot Multipart
- Standard Java I/O

### React (No New Dependencies)
- FormData API (built-in)
- File API (built-in)

## Known Limitations

1. **Browser-Based Constraints**
   - Cannot automatically detect sibling segments
   - User must select all segments manually
   - This is a browser security requirement

2. **File Size**
   - Configured max: 10 GB per file, 50 GB total
   - Adjust in `application.yml` if needed
   - Very large files require stable connection

3. **Upload Time**
   - Large images take time to upload
   - 1 GB ≈ 1-5 minutes (depends on connection)
   - Progress bar shows status

## Future Enhancements

### Phase 2 (Not Implemented Yet)
- Desktop agent for automatic segment detection
- Direct disk-to-disk evidence transfer
- Network-mounted evidence support
- Evidence deduplication
- Resume interrupted uploads

## Troubleshooting

### Issue: "Upload Failed"
**Solution:** Check backend logs, verify disk space, check file permissions

### Issue: "Segments don't match"
**Solution:** Ensure all selected files are from the same image (same base name)

### Issue: "pyewf not available"
**Solution:** Install Python dependencies:
```bash
cd ingestion
pip install -r forensic_requirements.txt
```

### Issue: "Timeout during upload"
**Solution:** Increase timeout in `api.js` or split large images

### Issue: "Permission denied writing to evidence-storage"
**Solution:** Ensure backend process has write permission to project directory

## Configuration

### Change Upload Limits
Edit `backend/src/main/resources/application.yml`:
```yaml
spring:
  servlet:
    multipart:
      max-file-size: 20GB      # Increase per-file limit
      max-request-size: 100GB  # Increase total request limit
```

### Change Storage Location
Edit `EvidenceStorageService.java`:
```java
private static final String EVIDENCE_STORAGE_BASE = "/mnt/evidence-storage";
```

### Change Upload Timeout
Edit `frontend/src/services/api.js`:
```javascript
timeout: 1200000, // 20 minutes
```

## Summary

This implementation provides a **real forensic evidence ingestion workflow** that:

✅ Uses native OS file picker (no manual path typing)  
✅ Supports split E01/EWF images properly  
✅ Handles large files safely (streaming, no memory issues)  
✅ Stores evidence in controlled storage  
✅ Integrates with existing parsers seamlessly  
✅ Preserves all existing functionality  
✅ Follows browser security best practices  
✅ Provides clear validation and error messages  

The investigator **never has to type a filesystem path** - they simply browse, select, and ingest.
