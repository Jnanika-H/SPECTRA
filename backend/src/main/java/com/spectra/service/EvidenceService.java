package com.spectra.service;

import com.spectra.dto.AnalyzeRequest;
import com.spectra.dto.IngestRequest;
import com.spectra.model.Evidence;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Instant;
import java.util.*;

@Slf4j
@Service
public class EvidenceService {

    private final MongoTemplate mongo;
    private final WebClient flaskWebClient;

    public EvidenceService(MongoTemplate mongo, WebClient flaskWebClient) {
        this.mongo = mongo;
        this.flaskWebClient = flaskWebClient;
    }

    public List<Evidence> ingest(IngestRequest req, String submitter) {
        List<Evidence> saved = new ArrayList<>();
        for (Map<String, Object> rawArt : req.getArtifacts()) {
            Evidence evidence = Evidence.builder()
                .caseId(req.getCaseId())
                .submittedBy(submitter)
                .submittedAt(Instant.now())
                .evidenceType(String.valueOf(rawArt.getOrDefault("type", "unknown")))
                .rawArtifact(rawArt)
                .features(extractFeatures(rawArt))
                .build();
            saved.add(mongo.save(evidence));
        }
        log.info("Ingested {} artifacts for case {}", saved.size(), req.getCaseId());
        return saved;
    }

    public Map<String, Object> analyze(AnalyzeRequest req, String investigator) {
        Query query = new Query(Criteria.where("caseId").is(req.getCaseId()));
        List<Evidence> evidenceList = mongo.find(query, Evidence.class);

        List<Map<String, Object>> scored = new ArrayList<>();
        int totalScore = 0;
        int anomalies = 0;

        for (Evidence ev : evidenceList) {
            try {
                // Call Flask /score
                Map<String, Object> scorePayload = new HashMap<>(ev.getFeatures());
                scorePayload.put("artifact_id", ev.getId());
                scorePayload.put("rule_score", getRuleScore(ev));

                Map scoreResult = callFlask("/score", scorePayload);
                Integer finalScore = (Integer) ((Map) scoreResult).getOrDefault("final_score", 0);
                String severity    = (String) ((Map) scoreResult).getOrDefault("severity", "low");

                // Call Flask /anomaly
                Map anomalyResult = callFlask("/anomaly", scorePayload);
                Boolean isAnomaly = (Boolean) ((Map) anomalyResult).getOrDefault("is_anomaly", false);

                // Update MongoDB
                ev.setMlScore((Integer) ((Map) scoreResult).getOrDefault("ml_score", 0));
                ev.setRuleScore((Integer) scorePayload.get("rule_score"));
                ev.setFinalScore(finalScore);
                ev.setSeverity(severity);
                ev.setIsAnomaly(isAnomaly);
                mongo.save(ev);

                totalScore += finalScore;
                if (Boolean.TRUE.equals(isAnomaly)) anomalies++;

                scored.add(Map.of(
                    "id", ev.getId(),
                    "type", ev.getEvidenceType(),
                    "finalScore", finalScore,
                    "severity", severity,
                    "isAnomaly", isAnomaly
                ));
            } catch (Exception e) {
                log.error("Failed to score evidence {}: {}", ev.getId(), e.getMessage());
            }
        }

        // Build timeline via Flask
        List<Map<String, Object>> rawArtifacts = evidenceList.stream()
            .map(Evidence::getRawArtifact).filter(Objects::nonNull).toList();
        Map timelineResult = Map.of();
        if (!rawArtifacts.isEmpty()) {
            try {
                timelineResult = callFlask("/timeline", Map.of("artifacts", rawArtifacts));
            } catch (Exception e) {
                log.warn("Timeline error: {}", e.getMessage());
            }
        }

        return Map.of(
            "caseId",           req.getCaseId(),
            "analyzed",         scored.size(),
            "anomalies",        anomalies,
            "averageScore",     scored.isEmpty() ? 0 : totalScore / scored.size(),
            "results",          scored,
            "timeline",         timelineResult
        );
    }

    @SuppressWarnings("unchecked")
    private Map callFlask(String endpoint, Map<String, Object> body) {
        return flaskWebClient.post()
            .uri(endpoint)
            .bodyValue(body)
            .retrieve()
            .bodyToMono(Map.class)
            .timeout(java.time.Duration.ofSeconds(30))
            .block();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Double> extractFeatures(Map<String, Object> raw) {
        Map<String, Object> features = (Map<String, Object>) raw.getOrDefault("features", Map.of());
        Map<String, Double> result = new HashMap<>();
        for (String key : List.of("network_activity", "session_time", "data_transfer", "connection_status")) {
            Object v = features.get(key);
            result.put(key, v instanceof Number ? ((Number) v).doubleValue() : 0.0);
        }
        return result;
    }

    private int getRuleScore(Evidence ev) {
        Object raw = ev.getRawArtifact();
        if (raw instanceof Map m) {
            Object rs = m.get("rule_score");
            if (rs instanceof Number n) return n.intValue();
        }
        return 0;
    }
}


