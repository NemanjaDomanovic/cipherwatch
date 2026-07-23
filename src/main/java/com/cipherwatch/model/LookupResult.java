package com.cipherwatch.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "lookup_results")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LookupResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "lookup_id", nullable = false)
    private ThreatLookup threatLookup;

    @Column(name = "source_name", nullable = false)
    private String sourceName;

    @Column(name = "raw_data", columnDefinition = "TEXT")
    private String rawData;

    @Column(name = "risk_contribution")
    private Integer riskContribution;

    @Column(name = "success")
    private Boolean success;

    @Column(name = "error_message")
    private String errorMessage;

    @Column(name = "queried_at")
    private LocalDateTime queriedAt;

    @PrePersist
    protected void onCreate() {
        queriedAt = LocalDateTime.now();
    }
}