package com.spectra.dto;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;
@Data @NoArgsConstructor @AllArgsConstructor
public class FeedbackRequest {
    @NotBlank private String evidenceId;
    private Integer correctedScore;
    private Integer correctedLabel;
    private String notes;
}
