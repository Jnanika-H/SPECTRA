package com.spectra.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

@Slf4j
@Service
public class EvidenceStorageService {

    private static final String EVIDENCE_STORAGE_BASE = "evidence-storage";
    private static final long MAX_FILE_SIZE = 1024L * 1024L * 1024L * 100L; // 100 GB

    public EvidenceStorageService() {
        // Ensure evidence storage directory exists
        try {
            Path storagePath = getStorageBasePath();
            if (!Files.exists(storagePath)) {
                Files.createDirectories(storagePath);
                log.info("Created evidence storage directory: {}", storagePath.toAbsolutePath());
            }
        } catch (IOException e) {
            log.error("Failed to create evidence storage directory", e);
        }
    }

    /**
     * Store uploaded forensic evidence files
     */
    public Map<String, Object> storeForensicEvidence(String caseId, List<MultipartFile> files) throws IOException {
        if (files == null || files.isEmpty()) {
            throw new IllegalArgumentException("No files provided");
        }

        // Create case-specific directory
        Path caseDir = getCaseDirectory(caseId);
        if (!Files.exists(caseDir)) {
            Files.createDirectories(caseDir);
            log.info("Created case directory: {}", caseDir);
        }

        List<Map<String, Object>> storedFiles = new ArrayList<>();
        long totalSize = 0;

        // Store each file
        for (MultipartFile file : files) {
            String originalFilename = file.getOriginalFilename();
            if (originalFilename == null || originalFilename.isEmpty()) {
                continue;
            }

            // Validate file size
            if (file.getSize() > MAX_FILE_SIZE) {
                throw new IOException("File too large: " + originalFilename + " (max 100GB)");
            }

            // Sanitize filename (prevent path traversal)
            String safeFilename = sanitizeFilename(originalFilename);
            Path targetPath = caseDir.resolve(safeFilename);

            // Check if file already exists
            if (Files.exists(targetPath)) {
                log.warn("File already exists, will overwrite: {}", targetPath);
            }

            // Store file with streaming to handle large files
            log.info("Storing evidence file: {} ({} MB)", safeFilename, file.getSize() / (1024 * 1024));
            
            try (InputStream in = file.getInputStream();
                 OutputStream out = Files.newOutputStream(targetPath, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }

            // Calculate hash
            String sha256 = calculateSHA256(targetPath);

            Map<String, Object> fileInfo = new HashMap<>();
            fileInfo.put("filename", safeFilename);
            fileInfo.put("original_filename", originalFilename);
            fileInfo.put("path", targetPath.toString());
            fileInfo.put("size_bytes", file.getSize());
            fileInfo.put("size_mb", file.getSize() / (1024.0 * 1024.0));
            fileInfo.put("sha256", sha256);
            fileInfo.put("stored_at", java.time.Instant.now());

            storedFiles.add(fileInfo);
            totalSize += file.getSize();

            log.info("Stored: {} (SHA-256: {})", safeFilename, sha256);
        }

        // Detect image format and segments
        String firstSegmentPath = (String) storedFiles.get(0).get("path");
        String imageFormat = detectImageFormat(firstSegmentPath);

        Map<String, Object> result = new HashMap<>();
        result.put("case_id", caseId);
        result.put("storage_path", caseDir.toString());
        result.put("files", storedFiles);
        result.put("segment_count", storedFiles.size());
        result.put("total_size_bytes", totalSize);
        result.put("total_size_gb", totalSize / (1024.0 * 1024.0 * 1024.0));
        result.put("image_format", imageFormat);
        result.put("first_segment", firstSegmentPath);

        return result;
    }

    /**
     * Get path to case directory
     */
    public Path getCaseDirectory(String caseId) {
        return getStorageBasePath().resolve(sanitizeFilename(caseId));
    }

    /**
     * Get base storage path
     */
    private Path getStorageBasePath() {
        // Get project root (parent of backend directory)
        String projectRoot = System.getProperty("user.dir");
        if (projectRoot.endsWith("backend")) {
            projectRoot = new File(projectRoot).getParent();
        }
        return Paths.get(projectRoot, EVIDENCE_STORAGE_BASE);
    }

    /**
     * Sanitize filename to prevent path traversal attacks
     */
    private String sanitizeFilename(String filename) {
        if (filename == null) {
            return "unknown";
        }
        // Remove path separators and parent directory references
        return filename.replaceAll("[/\\\\]", "_")
                      .replaceAll("\\.\\.", "_")
                      .replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    /**
     * Calculate SHA-256 hash of a file
     */
    private String calculateSHA256(Path filePath) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            
            try (InputStream fis = Files.newInputStream(filePath)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }
            
            byte[] hashBytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
            
        } catch (Exception e) {
            log.error("Failed to calculate SHA-256", e);
            return "ERROR";
        }
    }

    /**
     * Detect forensic image format from file extension
     */
    private String detectImageFormat(String filePath) {
        String filename = new File(filePath).getName().toLowerCase();
        
        if (filename.matches(".*\\.e\\d{2}$")) {
            return "E01/EWF";
        } else if (filename.matches(".*\\.ex\\d{2}$")) {
            return "E01/EWF";
        } else if (filename.endsWith(".dd") || filename.endsWith(".raw") || filename.endsWith(".img")) {
            return "RAW/DD";
        }
        
        return "UNKNOWN";
    }

    /**
     * Check if evidence exists for a case
     */
    public boolean evidenceExists(String caseId) {
        Path caseDir = getCaseDirectory(caseId);
        return Files.exists(caseDir) && Files.isDirectory(caseDir);
    }

    /**
     * Get list of stored evidence files for a case
     */
    public List<String> getStoredEvidenceFiles(String caseId) throws IOException {
        Path caseDir = getCaseDirectory(caseId);
        if (!Files.exists(caseDir)) {
            return Collections.emptyList();
        }

        List<String> files = new ArrayList<>();
        try (var stream = Files.list(caseDir)) {
            stream.filter(Files::isRegularFile)
                  .map(Path::toString)
                  .forEach(files::add);
        }
        
        return files;
    }
}
