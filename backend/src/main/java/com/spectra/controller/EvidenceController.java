package com.spectra.controller;

import com.spectra.dto.IngestRequest;
import com.spectra.dto.AnalyzeRequest;
import com.spectra.model.Evidence;
import com.spectra.service.EvidenceService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/ingest")
@RequiredArgsConstructor
public class EvidenceController {

    private final EvidenceService evidenceService;

    /**
     * POST /api/ingest
     * Accepts raw artifact(s), stores in MongoDB, queues for AI analysis.
     */
    @PostMapping
    public ResponseEntity<Map<String, Object>> ingest(
            @Valid @RequestBody IngestRequest req,
            Authentication auth) {
        List<Evidence> saved = evidenceService.ingest(req, auth.getName());
        return ResponseEntity.ok(Map.of(
            "status",    "ingested",
            "caseId",    req.getCaseId(),
            "count",     saved.size(),
            "evidenceIds", saved.stream().map(Evidence::getId).toList()
        ));
    }

    /**
     * POST /api/analyze
     * Runs AI scoring + anomaly detection on a case or specific evidence IDs.
     */
    @PostMapping("/analyze")
    public ResponseEntity<Map<String, Object>> analyze(
            @RequestBody AnalyzeRequest req,
            Authentication auth) {
        Map<String, Object> result = evidenceService.analyze(req, auth.getName());
        return ResponseEntity.ok(result);
    }
}


