package com.spectra.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import java.time.Instant;
import java.util.Map;

@Data @Builder @NoArgsConstructor @AllArgsConstructor
@Document(collection = "feedback")
public class Feedback {
    @Id
    private String id;
    private String  evidenceId;
    private String  investigator;
    private Instant submittedAt;
    private Integer originalScore;
    private Integer correctedScore;
    private Integer correctedLabel;
    private String  notes;
    private Map<String, Double> features;
    private Boolean usedForRetraining;
    private Instant retrainedAt;
}
