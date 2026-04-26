package com.spectra.service;

import com.spectra.dto.FeedbackRequest;
import com.spectra.model.Evidence;
import com.spectra.model.Feedback;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
public class FeedbackService {

    private final MongoTemplate mongo;
    private final WebClient flaskWebClient;

    private static final int RETRAIN_THRESHOLD = 50;

    public FeedbackService(MongoTemplate mongo, WebClient flaskWebClient) {
        this.mongo = mongo;
        this.flaskWebClient = flaskWebClient;
    }

    public Feedback submit(FeedbackRequest req, String investigator) {
        Evidence ev = mongo.findById(req.getEvidenceId(), Evidence.class);

        Feedback feedback = Feedback.builder()
            .evidenceId(req.getEvidenceId())
            .investigator(investigator)
            .submittedAt(Instant.now())
            .originalScore(ev != null ? ev.getFinalScore() : null)
            .correctedScore(req.getCorrectedScore())
            .correctedLabel(req.getCorrectedLabel())
            .notes(req.getNotes())
            .features(ev != null ? ev.getFeatures() : Map.of())
            .usedForRetraining(false)
            .build();

        Feedback saved = mongo.save(feedback);
        log.info("Feedback recorded: evidence={} by={}", req.getEvidenceId(), investigator);

        // Auto-retrain if threshold reached
        long pendingCount = mongo.count(
            new Query(Criteria.where("usedForRetraining").is(false)), Feedback.class
        );
        if (pendingCount >= RETRAIN_THRESHOLD) {
            log.info("Retrain threshold reached ({} samples). Triggering retrain.", pendingCount);
            triggerRetrain();
        }

        return saved;
    }

    public Map<String, Object> triggerRetrain() {
        List<Feedback> pending = mongo.find(
            new Query(Criteria.where("usedForRetraining").is(false)), Feedback.class
        );

        if (pending.size() < 20) {
            return Map.of("status", "skipped", "reason", "Insufficient feedback samples: " + pending.size());
        }

        List<Map<String, Object>> samples = pending.stream()
            .filter(f -> f.getFeatures() != null && f.getCorrectedLabel() != null)
            .map(f -> Map.of("features", (Object) f.getFeatures(), "label", f.getCorrectedLabel()))
            .collect(Collectors.toList());

        try {
            Map result = flaskWebClient.post()
                .uri("/retrain")
                .bodyValue(Map.of("samples", samples))
                .retrieve()
                .bodyToMono(Map.class)
                .block();

            // Mark feedback as used
            Instant now = Instant.now();
            for (Feedback f : pending) {
                f.setUsedForRetraining(true);
                f.setRetrainedAt(now);
                mongo.save(f);
            }
            log.info("Retrain complete: {} samples used", samples.size());
            return Map.of("status", "retrained", "samplesUsed", samples.size());
        } catch (Exception e) {
            log.error("Retrain failed: {}", e.getMessage());
            return Map.of("status", "error", "message", e.getMessage());
        }
    }
}
