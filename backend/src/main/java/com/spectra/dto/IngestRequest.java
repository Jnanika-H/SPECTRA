package com.spectra.dto;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import java.util.List;
import java.util.Map;
@Data @NoArgsConstructor @AllArgsConstructor
public class IngestRequest {
    @NotBlank private String caseId;
    private List<Map<String, Object>> artifacts;
    private String description;
}
