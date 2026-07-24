package com.cipherwatch.service.api;

import com.cipherwatch.dto.response.ApiResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@Service
public class VirusTotalService {

    @Value("${app.api.virustotal.key}")
    private String apiKey;

    private final HttpClient httpClient;

    public VirusTotalService(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public ApiResult checkIp(String ipAddress) {
        try {
            String url = "https://www.virustotal.com/api/v3/ip_addresses/" + ipAddress;

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("x-apikey", apiKey)
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString()
            );

            String body = response.body();
            int riskContribution = extractMaliciousScore(body);

            return ApiResult.builder()
                    .sourceName("VirusTotal")
                    .success(true)
                    .rawData(body)
                    .riskContribution(riskContribution)
                    .build();

        } catch (Exception e) {
            return ApiResult.builder()
                    .sourceName("VirusTotal")
                    .success(false)
                    .rawData("{}")
                    .riskContribution(0)
                    .errorMessage(e.getMessage())
                    .build();
        }
    }

    private int extractMaliciousScore(String json) {
        try {
            int idx = json.indexOf("\"malicious\":");
            if (idx == -1) return 0;
            String sub = json.substring(idx + 12).trim();
            StringBuilder num = new StringBuilder();
            for (char c : sub.toCharArray()) {
                if (Character.isDigit(c)) num.append(c);
                else break;
            }
            int maliciousCount = Integer.parseInt(num.toString());
            // Pretvaramo broj detektora u score 0-100
            // Ako 5+ antivirusa kaže malicious, to je 100
            return Math.min(maliciousCount * 20, 100);
        } catch (Exception e) {
            return 0;
        }
    }
}