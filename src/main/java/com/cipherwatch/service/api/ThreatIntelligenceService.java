package com.cipherwatch.service.api;

import com.cipherwatch.dto.response.ApiResult;
import com.cipherwatch.model.*;
import com.cipherwatch.repository.LookupResultRepository;
import com.cipherwatch.repository.ThreatLookupRepository;
import com.cipherwatch.service.api.AbuseIpdbService;
import com.cipherwatch.service.api.IpInfoService;
import com.cipherwatch.service.api.VirusTotalService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.*;

@Service
public class ThreatIntelligenceService {

    private final AbuseIpdbService abuseIpdbService;
    private final VirusTotalService virusTotalService;
    private final IpInfoService ipInfoService;
    private final ThreatLookupRepository lookupRepository;
    private final LookupResultRepository resultRepository;
    private final ExecutorService executorService;

    @Value("${app.risk.alert-threshold}")
    private int alertThreshold;

    public ThreatIntelligenceService(
            AbuseIpdbService abuseIpdbService,
            VirusTotalService virusTotalService,
            IpInfoService ipInfoService,
            ThreatLookupRepository lookupRepository,
            LookupResultRepository resultRepository,
            ExecutorService executorService) {
        this.abuseIpdbService = abuseIpdbService;
        this.virusTotalService = virusTotalService;
        this.ipInfoService = ipInfoService;
        this.lookupRepository = lookupRepository;
        this.resultRepository = resultRepository;
        this.executorService = executorService;
    }

    public ThreatLookup analyze(String inputValue, InputType inputType) {

        // 1. Sacuvaj lookup u bazu sa statusom "u toku"
        ThreatLookup lookup = ThreatLookup.builder()
                .inputValue(inputValue)
                .inputType(inputType)
                .riskScore(0)
                .riskLevel(RiskLevel.SAFE)
                .summary("Analiza u toku...")
                .build();
        lookup = lookupRepository.save(lookup);

        // 2. PARALELNI API POZIVI — srce projekta!
        // Umesto sekvencijalnog cekanja (3+3+3=9 sekundi),
        // saljemo sve 3 odjednom i cekamo najduzi (max 3 sekunde)
        Future<ApiResult> abuseIpdbFuture =
                executorService.submit(() -> abuseIpdbService.checkIp(inputValue));

        Future<ApiResult> virusTotalFuture =
                executorService.submit(() -> virusTotalService.checkIp(inputValue));

        Future<ApiResult> ipInfoFuture =
                executorService.submit(() -> ipInfoService.checkIp(inputValue));

        // 3. Prikupi rezultate (cekamo max 15 sekundi po API-ju)
        ApiResult abuseResult = getResult(abuseIpdbFuture, "AbuseIPDB");
        ApiResult vtResult = getResult(virusTotalFuture, "VirusTotal");
        ApiResult ipInfoResult = getResult(ipInfoFuture, "IpInfo");

        List<ApiResult> allResults = List.of(abuseResult, vtResult, ipInfoResult);

        // 4. Izracunaj finalni risk score
        int finalScore = calculateRiskScore(allResults);
        RiskLevel riskLevel = calculateRiskLevel(finalScore);
        String summary = generateSummary(inputValue, finalScore, riskLevel, allResults);

        // 5. Sacuvaj rezultate u bazu
        final ThreatLookup finalLookup = lookup;
        allResults.forEach(result -> {
            LookupResult lr = LookupResult.builder()
                    .threatLookup(finalLookup)
                    .sourceName(result.getSourceName())
                    .rawData(result.getRawData())
                    .riskContribution(result.getRiskContribution())
                    .success(result.isSuccess())
                    .errorMessage(result.getErrorMessage())
                    .build();
            resultRepository.save(lr);
        });

        // 6. Azuriraj lookup sa finalnim rezultatima
        lookup.setRiskScore(finalScore);
        lookup.setRiskLevel(riskLevel);
        lookup.setSummary(summary);
        lookup.setCompletedAt(LocalDateTime.now());
        return lookupRepository.save(lookup);
    }

    private ApiResult getResult(Future<ApiResult> future, String sourceName) {
        try {
            return future.get(15, TimeUnit.SECONDS);
        } catch (Exception e) {
            return ApiResult.builder()
                    .sourceName(sourceName)
                    .success(false)
                    .rawData("{}")
                    .riskContribution(0)
                    .errorMessage("Timeout ili greska: " + e.getMessage())
                    .build();
        }
    }

    private int calculateRiskScore(List<ApiResult> results) {
        // Tezinski prosek: AbuseIPDB ima najveci uticaj
        int abuseScore = results.get(0).getRiskContribution();
        int vtScore = results.get(1).getRiskContribution();
        int ipInfoScore = results.get(2).getRiskContribution();

        // AbuseIPDB 50%, VirusTotal 35%, IpInfo 15%
        return (int) (abuseScore * 0.50 + vtScore * 0.35 + ipInfoScore * 0.15);
    }

    private RiskLevel calculateRiskLevel(int score) {
        if (score <= 30) return RiskLevel.SAFE;
        if (score <= 50) return RiskLevel.LOW;
        if (score <= 70) return RiskLevel.MEDIUM;
        if (score <= 85) return RiskLevel.HIGH;
        return RiskLevel.CRITICAL;
    }

    private String generateSummary(String input, int score,
                                   RiskLevel level, List<ApiResult> results) {
        long successCount = results.stream().filter(ApiResult::isSuccess).count();
        return String.format(
                "Analiza za '%s' zavrsena. Risk score: %d/100 (%s). " +
                        "Uspesno kontaktirano %d/3 izvora. " +
                        "AbuseIPDB: %d, VirusTotal: %d, IpInfo: %d.",
                input, score, level.name(),
                successCount,
                results.get(0).getRiskContribution(),
                results.get(1).getRiskContribution(),
                results.get(2).getRiskContribution()
        );
    }

    public List<ThreatLookup> getRecentLookups() {
        return lookupRepository.findTop10ByOrderByCreatedAtDesc();
    }

    public ThreatLookup getLookupById(Long id) {
        return lookupRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Lookup nije pronadjen: " + id));
    }
}