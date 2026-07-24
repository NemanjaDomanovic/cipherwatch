package com.cipherwatch.service.api;

import com.cipherwatch.dto.response.ApiResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@Service
public class AbuseIpdbService {

    @Value("${app.api.abuseipdb.key}")
    private String apiKey;

    private final HttpClient httpClient;

    public AbuseIpdbService(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public ApiResult checkIp(String ipAddress) {
        try {
            String url = "https://api.abuseipdb.com/api/v2/check?ipAddress="
                    + ipAddress + "&maxAgeInDays=90&verbose";

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Key", apiKey)
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString()
            );

            String body = response.body();
            int riskContribution = extractAbuseScore(body);

            return ApiResult.builder()
                    .sourceName("AbuseIPDB")
                    .success(true)
                    .rawData(body)
                    .riskContribution(riskContribution)
                    .build();

        } catch (Exception e) {
            return ApiResult.builder()
                    .sourceName("AbuseIPDB")
                    .success(false)
                    .rawData("{}")
                    .riskContribution(0)
                    .errorMessage(e.getMessage())
                    .build();
        }
    }

    private int extractAbuseScore(String json) {
        try {
            int idx = json.indexOf("\"abuseConfidenceScore\":");
            if (idx == -1) return 0;
            String sub = json.substring(idx + 23).trim();
            StringBuilder num = new StringBuilder();
            for (char c : sub.toCharArray()) {
                if (Character.isDigit(c)) num.append(c);
                else break;
            }
            return Integer.parseInt(num.toString());
        } catch (Exception e) {
            return 0;
        }
    }
}