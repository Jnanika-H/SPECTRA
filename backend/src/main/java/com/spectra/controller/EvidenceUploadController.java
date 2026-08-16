package com.spectra.controller;

import com.spectra.service.EvidenceService;
import com.spectra.service.EvidenceStorageService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.*;

@Slf4j
@RestController
@RequestMapping("/evidence")
@RequiredArgsConstructor
public class EvidenceUploadController {

    private final EvidenceStorageService storageService;
    private final EvidenceService evidenceService;

    /**
     * POST /api/evidence/upload
     * Upload forensic evidence files (E01/EWF segments or RAW/DD images)
     */
    @PostMapping("/upload")
    public ResponseEntity<Map<String, Object>> uploadForensicEvidence(
            @RequestParam("caseId") String caseId,
            @RequestParam("evidenceFiles") List<MultipartFile> files,
            Authentication auth) {
        
        try {
            log.info("Received forensic evidence upload for case: {} ({} files)", caseId, files.size());
            log.info("Uploaded by: {}", auth.getName());

            // Store files in controlled evidence storage
            Map<String, Object> storageResult = storageService.storeForensicEvidence(caseId, files);
            
            log.info("Evidence stored successfully: {} segments, {} GB",
                    storageResult.get("segment_count"),
                    storageResult.get("total_size_gb"));

            // Build config for forensic collector
            String firstSegmentPath = (String) storageResult.get("first_segment");
            
            Map<String, Object> config = new HashMap<>();
            config.put("case_id", caseId);
            config.put("image_path", firstSegmentPath);
            config.put("image_type", "disk_image");
            config.put("max_files", 1000);
            
            // Trigger forensic collection
            List<Map<String, Object>> artifacts = Collections.singletonList(
                Map.of("mode", "collect_forensic", "config", config)
            );
            
            // Process artifacts through evidence service
            com.spectra.dto.IngestRequest ingestReq = new com.spectra.dto.IngestRequest();
            ingestReq.setCaseId(caseId);
            ingestReq.setArtifacts(artifacts);
            
            evidenceService.ingest(ingestReq, auth.getName());

            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("case_id", caseId);
            response.put("storage", storageResult);
            response.put("message", "Forensic evidence uploaded and processed successfully");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Failed to upload forensic evidence", e);
            return ResponseEntity.status(500).body(Map.of(
                "status", "error",
                "message", "Upload failed: " + e.getMessage()
            ));
        }
    }

    /**
     * GET /api/evidence/validate
     * Validate forensic evidence files before upload
     */
    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateForensicEvidence(
            @RequestParam("evidenceFiles") List<MultipartFile> files) {
        
        try {
            log.info("Validating {} evidence files", files.size());

            List<Map<String, String>> fileInfo = new ArrayList<>();
            long totalSize = 0;
            
            for (MultipartFile file : files) {
                Map<String, String> info = new HashMap<>();
                info.put("filename", file.getOriginalFilename());
                info.put("size", String.valueOf(file.getSize()));
                info.put("content_type", file.getContentType());
                fileInfo.add(info);
                totalSize += file.getSize();
            }

            Map<String, Object> response = new HashMap<>();
            response.put("valid", true);
            response.put("files", fileInfo);
            response.put("total_size_bytes", totalSize);
            response.put("total_size_gb", totalSize / (1024.0 * 1024.0 * 1024.0));

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Validation failed", e);
            return ResponseEntity.status(400).body(Map.of(
                "valid", false,
                "error", e.getMessage()
            ));
        }
    }
}
