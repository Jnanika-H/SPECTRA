// ── Evidence.java ──────────────────────────────────────────────────────────
package com.spectra.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.index.Indexed;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "evidence")
public class Evidence {

    @Id
    private String id;

    @Indexed
    private String caseId;

    private String submittedBy;       // investigator username
    private Instant submittedAt;

    private String evidenceType;      // file | event_log | browser_history | network_packet
    private String sourcePath;
    
    // NEW: Forensic evidence metadata
    private String evidenceSourceType;  // SYSTEM_PATH | FORENSIC_IMAGE
    private String forensicImagePath;   // Path to forensic image (if applicable)
    private String forensicImageFormat; // E01/EWF | RAW/DD
    private Integer forensicSegmentCount; // Number of image segments
    private String forensicFilesystemType; // NTFS | FAT32 | EXT4 | etc.
    private Long forensicInode;         // Inode number in forensic image

    // Raw artifact payload from evidence collector
    private Map<String, Object> rawArtifact;

    // ML feature vector
    private Map<String, Double> features;

    // Scores
    private Integer mlScore;
    private Integer ruleScore;
    private Integer finalScore;
    private String  severity;         // critical | high | medium | low | informational
    private Boolean isAnomaly;
    private Double  anomalyScore;

    // Timestamps extracted from artifact
    private Instant evidenceTimestamp;

    // Blockchain
    private String reportHash;
    private String txHash;
    private Boolean blockchainVerified;

    private List<String> tags;
    private String notes;
}
