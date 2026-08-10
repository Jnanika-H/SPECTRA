package com.spectra.repository;

import com.spectra.model.Evidence;
import com.spectra.model.ForensicReport;
import com.spectra.model.Feedback;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

// ── EvidenceRepository ───────────────────────────────────────────────────────
@Repository
public interface EvidenceRepository extends MongoRepository<Evidence, String> {
    List<Evidence> findByCaseId(String caseId);
    long countByCaseId(String caseId);
}

// ── ForensicReportRepository ─────────────────────────────────────────────────
@Repository
interface ForensicReportRepository extends MongoRepository<ForensicReport, String> {
    Optional<ForensicReport> findByCaseId(String caseId);
    List<ForensicReport> findAllByOrderByCreatedAtDesc();
}

// ── FeedbackRepository ───────────────────────────────────────────────────────
@Repository
interface FeedbackRepository extends MongoRepository<Feedback, String> {
    List<Feedback> findByUsedForRetrainingFalse();
    long countByUsedForRetrainingFalse();
    List<Feedback> findByEvidenceId(String evidenceId);
}
