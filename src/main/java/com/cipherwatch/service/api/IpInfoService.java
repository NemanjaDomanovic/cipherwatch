package com.cipherwatch.service.api;

import com.cipherwatch.dto.response.ApiResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@Service
public class IpInfoService {

    @Value("${app.api.ipinfo.token}")
    private String token;

    private final HttpClient httpClient;

    public IpInfoService(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public ApiResult checkIp(String ipAddress) {
        try {
            String url = "https://ipinfo.io/" + ipAddress + "?token=" + token;

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString()
            );

            String body = response.body();
            int riskContribution = extractRiskFromIpInfo(body);

            return ApiResult.builder()
                    .sourceName("IpInfo")
                    .success(true)
                    .rawData(body)
                    .riskContribution(riskContribution)
                    .build();

        } catch (Exception e) {
            return ApiResult.builder()
                    .sourceName("IpInfo")
                    .success(false)
                    .rawData("{}")
                    .riskContribution(0)
                    .errorMessage(e.getMessage())
                    .build();
        }
    }

    private int extractRiskFromIpInfo(String json) {
        // IpInfo nam daje geolokaciju i organizaciju
        // Ako je Tor exit node, VPN ili hosting provider — viši risk
        int risk = 0;
        String lower = json.toLowerCase();
        if (lower.contains("tor")) risk += 40;
        if (lower.contains("vpn")) risk += 30;
        if (lower.contains("hosting")) risk += 20;
        if (lower.contains("datacenter")) risk += 15;
        if (lower.contains("proxy")) risk += 25;
        return Math.min(risk, 100);
    }
}