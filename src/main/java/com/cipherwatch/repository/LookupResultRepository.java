package com.cipherwatch.repository;

import com.cipherwatch.model.LookupResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LookupResultRepository extends JpaRepository<LookupResult, Long> {

    List<LookupResult> findByThreatLookupId(Long lookupId);

    List<LookupResult> findBySourceName(String sourceName);
}