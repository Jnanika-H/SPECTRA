# SPECTRA Forensic Disk Image Support

## Overview

SPECTRA now supports **browser-based forensic disk image ingestion** with a native file picker interface. Investigators can upload and analyze evidence from seized computers through forensic images (E01/EWF, RAW/DD) using a simple Browse button - **no manual path typing required**.

**Supports both:**
- ✅ Single complete E01 images (one file)
- ✅ Split E01/EWF images (multiple segments: E01, E02, E03, etc.)
- ✅ RAW/DD disk images
- ✅ No hard-coded segment limits (supports 1 to 9999+ segments)

## Quick Start

### Using Forensic Images in SPECTRA

1. **Navigate to Ingest Tab**
   - Click "Forensic Image" tab

2. **Select Evidence**
   - Click "Browse for Evidence" button
   - Windows file picker opens
   - Navigate to your evidence folder
   - Select forensic image file(s):
     - **Single E01**: Select just CASE.E01 (if it's complete)
     - **Split E01**: Select ALL segments (CASE.E01, CASE.E02, CASE.E03, etc.)
   
3. **For Split Images (E01 segments):**
   - Hold Ctrl and select all segments
   - Example: Select CASE.E01, CASE.E02, CASE.E03 together
   - SPECTRA will detect format and validate completeness using pyewf

4. **Validate (Optional)**
   - Click "Validate Evidence" to check segments
   - System will verify the EWF image is complete
   - Reports any missing segments

5. **Ingest**
   - Click "Ingest into CASE-XXX"
   - Files upload to secure storage (progress shown)
   - Evidence automatically validated using forensic library
   - Artifacts extracted and stored

6. **Analyze**
   - Click "Run Analysis" to process artifacts
   - View results in Evidence table
   - Timeline shows events from forensic image

## Architecture

```
Browser File Picker
        ↓
Upload to Secure Storage
        ↓
Evidence Sources
├── System Paths (existing) ──┐
│                              │
└── Forensic Disk Image (NEW) ─┤
                                ↓
                    Common Artifact Interface
                                ↓
                    Existing SPECTRA Pipeline

      