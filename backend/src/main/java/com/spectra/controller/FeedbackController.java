package com.spectra.controller;

import com.spectra.dto.FeedbackRequest;
import com.spectra.model.Feedback;
import com.spectra.service.FeedbackService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/feedback")
@RequiredArgsConstructor
public class FeedbackController {

    private final FeedbackService feedbackService;

    /**
     * POST /api/feedback
     * Body: { evidenceId, correctedScore, correctedLabel, notes }
     */
    @PostMapping
    public ResponseEntity<Map<String, Object>> submitFeedback(
            @Valid @RequestBody FeedbackRequest req,
            Authentication auth) {
        Feedback feedback = feedbackService.submit(req, auth.getName());
        return ResponseEntity.ok(Map.of(
            "status",     "recorded",
            "feedbackId", feedback.getId(),
            "message",    "Feedback stored. Model will retrain when threshold reached."
        ));
    }

    /** POST /api/feedback/trigger-retrain (admin only) */
    @PostMapping("/trigger-retrain")
    public ResponseEntity<Map<String, Object>> triggerRetrain(Authentication auth) {
        Map<String, Object> result = feedbackService.triggerRetrain();
        return ResponseEntity.ok(result);
    }
}


