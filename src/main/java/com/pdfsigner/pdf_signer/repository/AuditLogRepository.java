package com.pdfsigner.pdf_signer.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.pdfsigner.pdf_signer.model.AuditLog;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findByUserIdOrderByCreatedAtDesc(Long userId);

    List<AuditLog> findByEventTypeOrderByCreatedAtDesc(String eventType);

    List<AuditLog> findByUserEmailOrderByCreatedAtDesc(String userEmail);

    List<AuditLog> findByCreatedAtBetween(LocalDateTime start, LocalDateTime end);

    long countByEventTypeAndCreatedAtBetween(String eventType, LocalDateTime start, LocalDateTime end);

    @Query("SELECT al FROM AuditLog al WHERE al.createdAt < :date")
    List<AuditLog> findOlderThan(@Param("date") LocalDateTime date);

    @Modifying
    @Query("DELETE FROM AuditLog al WHERE al.createdAt < :date")
    void deleteOlderThan(@Param("date") LocalDateTime date);
}