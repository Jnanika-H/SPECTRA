// ── ForensicReport.java ─────────────────────────────────────────────────────
package com.spectra.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.index.Indexed;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Data @Builder @NoArgsConstructor @AllArgsConstructor
@Document(collection = "reports")
public class ForensicReport {
    @Id
    private String id;

    @Indexed(unique = true)
    private String caseId;

    private String title;
    private String investigator;
    private Instant createdAt;
    private Instant updatedAt;

    private String status;    // draft | finalized | archived

    private Integer totalEvidence;
    private Integer criticalCount;
    private Integer highCount;
    private Integer anomalyCount;
    private Double  averageThreatScore;

    private List<String> evidenceIds;

    // Timeline
    private Map<String, Object> timeline;

    // Blockchain integrity
    private String reportHash;          // SHA-256 of report content
    private String blockchainTxHash;    // Ethereum tx hash
    private Boolean verified;
    private Instant blockchainTimestamp;

    private String summary;
    private String conclusion;
    private List<String> recommendations;
}
