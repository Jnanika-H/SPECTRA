package com.spectra.dto;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import java.util.List;
@Data @NoArgsConstructor @AllArgsConstructor
public class AnalyzeRequest {
    @NotBlank private String caseId;
    private List<String> evidenceIds;
}
