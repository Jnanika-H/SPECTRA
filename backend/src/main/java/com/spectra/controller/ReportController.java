package com.spectra.controller;

import com.spectra.model.ForensicReport;
import com.spectra.service.ReportService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/reports")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;

    /** GET /api/reports */
    @GetMapping
    public ResponseEntity<List<ForensicReport>> getAllReports(Authentication auth) {
        return ResponseEntity.ok(reportService.getAll());
    }

    /** GET /api/reports/{id} */
    @GetMapping("/{id}")
    public ResponseEntity<ForensicReport> getReport(@PathVariable String id) {
        return reportService.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    /** POST /api/reports  (generate report for a case) */
    @PostMapping
    public ResponseEntity<ForensicReport> generateReport(
            @RequestBody Map<String, String> body,
            Authentication auth) {
        ForensicReport report = reportService.generate(body.get("caseId"), auth.getName());
        return ResponseEntity.ok(report);
    }
}


