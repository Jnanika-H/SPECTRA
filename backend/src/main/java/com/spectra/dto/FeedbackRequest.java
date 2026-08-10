package com.spectra.dto;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import jakarta.validation.constraints.NotNull;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class FeedbackRequest {

    @NotNull
    private Long evidenceId;

    private Integer correctedScore;

    private String correctedLabel;

    private String notes;
}