package com.spectra.service;

import com.spectra.model.Evidence;
import com.spectra.model.ForensicReport;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class ReportService {

    private final MongoTemplate mongo;
    private final BlockchainService blockchainService;

    public List<ForensicReport> getAll() {
        return mongo.findAll(ForensicReport.class);
    }

    public Optional<ForensicReport> findById(String id) {
        return Optional.ofNullable(mongo.findById(id, ForensicReport.class));
    }

    public ForensicReport generate(String caseId, String investigator) {
        List<Evidence> evidenceList = mongo.find(
            new Query(Criteria.where("caseId").is(caseId)), Evidence.class
        );

        if (evidenceList.isEmpty()) {
            throw new IllegalArgumentException("No evidence found for case: " + caseId);
        }

        // Statistics
        long critCount = evidenceList.stream().filter(e -> "critical".equals(e.getSeverity())).count();
        long highCount  = evidenceList.stream().filter(e -> "high".equals(e.getSeverity())).count();
        long anomCount  = evidenceList.stream().filter(e -> Boolean.TRUE.equals(e.getIsAnomaly())).count();
        double avgScore = evidenceList.stream()
            .filter(e -> e.getFinalScore() != null)
            .mapToInt(Evidence::getFinalScore).average().orElse(0.0);

        // Generate SHA-256 report hash
        String reportContent = buildReportContent(caseId, evidenceList);
        String hash = sha256(reportContent);

        ForensicReport report = ForensicReport.builder()
            .caseId(caseId)
            .title("Forensic Report — Case " + caseId)
            .investigator(investigator)
            .createdAt(Instant.now())
            .updatedAt(Instant.now())
            .status("finalized")
            .totalEvidence(evidenceList.size())
            .criticalCount((int) critCount)
            .highCount((int) highCount)
            .anomalyCount((int) anomCount)
            .averageThreatScore(avgScore)
            .evidenceIds(evidenceList.stream().map(Evidence::getId).toList())
            .reportHash(hash)
            .verified(false)
            .build();

        ForensicReport saved = mongo.save(report);

        // Store hash on blockchain
        try {
            Map<String, Object> txResult = blockchainService.storeHash(saved.getId(), hash);
            saved.setBlockchainTxHash((String) txResult.get("txHash"));
            saved.setVerified(true);
            saved.setBlockchainTimestamp(Instant.now());
            mongo.save(saved);
        } catch (Exception e) {
            log.warn("Blockchain store failed (non-fatal): {}", e.getMessage());
        }

        log.info("Report generated for case {}: {} evidence, hash={}", caseId, evidenceList.size(), hash);
        return saved;
    }

    private String buildReportContent(String caseId, List<Evidence> evidence) {
        StringBuilder sb = new StringBuilder();
        sb.append("CASE:").append(caseId).append("\n");
        sb.append("GENERATED:").append(Instant.now()).append("\n");
        for (Evidence e : evidence) {
            sb.append(e.getId()).append("|").append(e.getEvidenceType())
              .append("|").append(e.getFinalScore()).append("\n");
        }
        return sb.toString();
    }

    private String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (Exception e) {
            return UUID.randomUUID().toString();
        }
    }
}


