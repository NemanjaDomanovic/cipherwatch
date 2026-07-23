package com.cipherwatch.repository;

import com.cipherwatch.model.InputType;
import com.cipherwatch.model.ThreatLookup;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ThreatLookupRepository extends JpaRepository<ThreatLookup, Long> {

    List<ThreatLookup> findByInputValueOrderByCreatedAtDesc(String inputValue);

    List<ThreatLookup> findByInputTypeOrderByCreatedAtDesc(InputType inputType);

    List<ThreatLookup> findTop10ByOrderByCreatedAtDesc();
}