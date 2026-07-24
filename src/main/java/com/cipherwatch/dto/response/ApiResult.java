package com.cipherwatch.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiResult {
    private String sourceName;
    private boolean success;
    private String rawData;
    private int riskContribution;
    private String errorMessage;
}