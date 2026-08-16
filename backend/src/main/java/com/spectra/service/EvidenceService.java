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
        List<Map<String, Object>> artifacts = req.getArtifacts();
        
        // Check if this is a forensic image collection request
        if (artifacts.size() == 1 && artifacts.get(0).containsKey("mode")) {
            String mode = (String) artifacts.get(0).get("mode");
            
            if ("collect_forensic".equals(mode)) {
                // Call Python forensic evidence collector
                Map<String, Object> config = (Map<String, Object>) artifacts.get(0).get("config");
                Map<String, Object> forensicResult = collectForensicEvidence(config);
                
                if ("success".equals(forensicResult.get("status"))) {
                    artifacts = (List<Map<String, Object>>) forensicResult.get("artifacts");
                    Map<String, Object> metadata = (Map<String, Object>) forensicResult.get("metadata");
                    
                    log.info("Collected {} artifacts from forensic image", artifacts.size());
                    log.info("Image format: {}", metadata.get("image_format"));
                    log.info("Filesystem: {}", metadata.get("filesystem_type"));
                    
                    // Store evidence with forensic metadata
                    for (Map<String, Object> rawArt : artifacts) {
                        // Add forensic source metadata
                        rawArt.put("evidence_source_type", "FORENSIC_IMAGE");
                        rawArt.put("forensic_metadata", metadata);
                        
                        Evidence evidence = buildEvidenceFromArtifact(req.getCaseId(), submitter, rawArt);
                        saved.add(mongo.save(evidence));
                    }
                } else {
                    log.error("Forensic collection failed: {}", forensicResult.get("error"));
                    throw new RuntimeException("Forensic collection failed: " + forensicResult.get("error"));
                }
                
                return saved;
            } else if ("collect".equals(mode)) {
                // Existing system path collection
                Map<String, Object> config = (Map<String, Object>) artifacts.get(0).get("config");
                artifacts = collectRealEvidence(config);
                log.info("Collected {} real artifacts from paths", artifacts.size());
            }
        }
        
        // Process artifacts (either from demo, system paths, or forensic image)
        for (Map<String, Object> rawArt : artifacts) {
            Evidence evidence = buildEvidenceFromArtifact(req.getCaseId(), submitter, rawArt);
            saved.add(mongo.save(evidence));
        }
        
        log.info("Ingested {} artifacts for case {}", saved.size(), req.getCaseId());
        return saved;
    }
    
    private Evidence buildEvidenceFromArtifact(String caseId, String submitter, Map<String, Object> rawArt) {
        Evidence.EvidenceBuilder builder = Evidence.builder()
            .caseId(caseId)
            .submittedBy(submitter)
            .submittedAt(Instant.now())
            .evidenceType(String.valueOf(rawArt.getOrDefault("type", "unknown")))
            .rawArtifact(rawArt)
            .features(extractFeatures(rawArt));
        
        // Add forensic metadata if present
        String sourceType = (String) rawArt.get("evidence_source_type");
        if ("FORENSIC_IMAGE".equals(sourceType)) {
            builder.evidenceSourceType("FORENSIC_IMAGE");
            
            Map<String, Object> forensicMeta = (Map<String, Object>) rawArt.get("forensic_metadata");
            if (forensicMeta != null) {
                builder.forensicImagePath((String) forensicMeta.get("image_path"));
                builder.forensicImageFormat((String) forensicMeta.get("image_format"));
                builder.forensicSegmentCount(((Number) forensicMeta.getOrDefault("segment_count", 1)).intValue());
                builder.forensicFilesystemType((String) forensicMeta.get("filesystem_type"));
            }
            
            // Store inode if available
            Object inode = rawArt.get("inode");
            if (inode instanceof Number) {
                builder.forensicInode(((Number) inode).longValue());
            }
        } else {
            builder.evidenceSourceType("SYSTEM_PATH");
        }
        
        return builder.build();
    }
    
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> collectRealEvidence(Map<String, Object> config) {
        java.io.File tempFile = null;
        try {
            // Add max_files limit to config (default 1000)
            if (!config.containsKey("max_files")) {
                config.put("max_files", 1000);
            }
            
            // Call Python evidence collector script
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            String configJson = mapper.writeValueAsString(config);
            
            // Write config to temporary file (avoids Windows command-line escaping issues)
            tempFile = java.io.File.createTempFile("spectra_config_", ".json");
            java.nio.file.Files.write(tempFile.toPath(), configJson.getBytes());
            
            // Get the project root directory (parent of backend folder)
            String projectRoot = System.getProperty("user.dir");
            if (projectRoot.endsWith("backend")) {
                projectRoot = new java.io.File(projectRoot).getParent();
            }
            String scriptPath = projectRoot + java.io.File.separator + "ingestion" + 
                               java.io.File.separator + "evidence_collector.py";
            
            log.info("Calling Python script at: {}", scriptPath);
            log.info("Config: max_files={}, paths={}", config.get("max_files"), 
                config.keySet().stream().filter(k -> k.endsWith("_path")).toList());
            
            ProcessBuilder pb = new ProcessBuilder(
                "python", 
                scriptPath,
                "--config-file", tempFile.getAbsolutePath()
            );
            // DO NOT redirect error stream - we need to read them separately
            // pb.redirectErrorStream(true);  // REMOVED - this was causing logs to mix with JSON
            Process process = pb.start();
            
            // Read output - separate JSON from logs
            java.io.BufferedReader stdoutReader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getInputStream())
            );
            java.io.BufferedReader stderrReader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getErrorStream())
            );
            
            // Read stderr (logs) in a separate thread
            StringBuilder logs = new StringBuilder();
            Thread logThread = new Thread(() -> {
                try {
                    String line;
                    while ((line = stderrReader.readLine()) != null) {
                        logs.append(line).append("\n");
                        // Log progress messages from Python
                        if (line.contains("Progress:") || line.contains("Scanning") || 
                            line.contains("complete") || line.contains("artifacts")) {
                            log.info("Python: {}", line);
                        }
                    }
                } catch (Exception e) {
                    log.error("Error reading stderr: {}", e.getMessage());
                }
            });
            logThread.start();
            
            // Read stdout (JSON only)
            StringBuilder jsonOutput = new StringBuilder();
            String line;
            while ((line = stdoutReader.readLine()) != null) {
                jsonOutput.append(line);
            }
            
            int exitCode = process.waitFor();
            logThread.join(1000); // Wait for log thread to finish
            
            // Clean up temp file
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
            
            if (exitCode != 0) {
                log.error("Evidence collector failed with exit code {}", exitCode);
                log.error("Logs: {}", logs.toString());
                return new ArrayList<>();
            }
            
            // Parse JSON output
            String jsonStr = jsonOutput.toString();
            log.info("Received {} bytes from evidence collector", jsonStr.length());
            
            return mapper.readValue(jsonStr, 
                mapper.getTypeFactory().constructCollectionType(List.class, Map.class));
                
        } catch (Exception e) {
            log.error("Failed to collect real evidence: {}", e.getMessage(), e);
            // Clean up temp file on error
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
            return new ArrayList<>();
        }
    }
    
    @SuppressWarnings("unchecked")
    private Map<String, Object> collectForensicEvidence(Map<String, Object> config) {
        java.io.File tempFile = null;
        try {
            // Call Python forensic evidence collector script
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            String configJson = mapper.writeValueAsString(config);
            
            // Write config to temporary file
            tempFile = java.io.File.createTempFile("spectra_forensic_config_", ".json");
            java.nio.file.Files.write(tempFile.toPath(), configJson.getBytes());
            
            // Get the project root directory
            String projectRoot = System.getProperty("user.dir");
            if (projectRoot.endsWith("backend")) {
                projectRoot = new java.io.File(projectRoot).getParent();
            }
            String scriptPath = projectRoot + java.io.File.separator + "ingestion" + 
                               java.io.File.separator + "forensic_evidence_collector.py";
            
            log.info("Calling forensic Python script at: {}", scriptPath);
            log.info("Case ID: {}, Image: {}", config.get("case_id"), config.get("image_path"));
            
            ProcessBuilder pb = new ProcessBuilder(
                "python", 
                scriptPath,
                "--config-file", tempFile.getAbsolutePath()
            );
            Process process = pb.start();
            
            // Read output - separate JSON from logs
            java.io.BufferedReader stdoutReader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getInputStream())
            );
            java.io.BufferedReader stderrReader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getErrorStream())
            );
            
            // Read stderr (logs) in a separate thread
            StringBuilder logs = new StringBuilder();
            Thread logThread = new Thread(() -> {
                try {
                    String line;
                    while ((line = stderrReader.readLine()) != null) {
                        logs.append(line).append("\n");
                        // Log important messages
                        if (line.contains("INFO") || line.contains("ERROR") || 
                            line.contains("WARNING") || line.contains("Progress")) {
                            log.info("Forensic: {}", line);
                        }
                    }
                } catch (Exception e) {
                    log.error("Error reading forensic stderr: {}", e.getMessage());
                }
            });
            logThread.start();
            
            // Read stdout (JSON only)
            StringBuilder jsonOutput = new StringBuilder();
            String line;
            while ((line = stdoutReader.readLine()) != null) {
                jsonOutput.append(line);
            }
            
            int exitCode = process.waitFor();
            logThread.join(1000);
            
            // Clean up temp file
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
            
            if (exitCode != 0) {
                log.error("Forensic collector failed with exit code {}", exitCode);
                log.error("Logs: {}", logs.toString());
                return Map.of("status", "error", "error", "Forensic collection script failed");
            }
            
            // Parse JSON output
            String jsonStr = jsonOutput.toString();
            log.info("Received {} bytes from forensic collector", jsonStr.length());
            
            return mapper.readValue(jsonStr, Map.class);
                
        } catch (Exception e) {
            log.error("Failed to collect forensic evidence: {}", e.getMessage(), e);
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
            return Map.of("status", "error", "error", e.getMessage());
        }
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
                    "isAnomaly", isAnomaly,
                    "rawArtifact", ev.getRawArtifact() != null ? ev.getRawArtifact() : Map.of()
                ));
            } catch (Exception e) {
                log.error("Failed to score evidence {}: {}", ev.getId(), e.getMessage());
            }
        }

        // Build timeline via Flask
        List<Map<String, Object>> rawArtifacts = evidenceList.stream()
            .map(Evidence::getRawArtifact).filter(Objects::nonNull).toList();
        Map timelineData = Map.of();
        if (!rawArtifacts.isEmpty()) {
            try {
                Map timelineResponse = callFlask("/timeline", Map.of("artifacts", rawArtifacts));
                // Extract timeline data from Flask response
                if (timelineResponse != null && timelineResponse.containsKey("timeline")) {
                    timelineData = (Map) timelineResponse.get("timeline");
                    log.info("Timeline received with {} events", 
                        timelineData.containsKey("events") ? ((List)timelineData.get("events")).size() : 0);
                }
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
            "timeline",         timelineData
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


