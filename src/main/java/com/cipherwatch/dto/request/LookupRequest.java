package com.cipherwatch.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LookupRequest {

    @NotBlank(message = "Input value ne sme biti prazan")
    @Size(min = 1, max = 500, message = "Input value mora biti izmedju 1 i 500 karaktera")
    private String inputValue;
}