package com.pdfsigner.pdf_signer.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.pdfsigner.pdf_signer.model.TokenType;
import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.model.VerificationToken;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

    Optional<VerificationToken> findByToken(String token);

    // Optional<VerificationToken> findByTokenAndTokenType(String token, TokenType
    // tokenType);

    @Query("SELECT vt FROM VerificationToken vt WHERE vt.token = :token AND vt.tokenType = :tokenType")
    Optional<VerificationToken> findByTokenAndTokenType(
            @Param("token") String token,
            @Param("tokenType") TokenType tokenType);

    Optional<VerificationToken> findByUserAndTokenType(User user, TokenType tokenType);

    List<VerificationToken> findAllByExpiryDateBefore(LocalDateTime date);

    void deleteByUser(User user);

    Integer deleteByExpiryDateBefore(LocalDateTime date);

    boolean existsByUserAndTokenType(User user, TokenType tokenType);

    @Modifying
    @Query("DELETE FROM VerificationToken vt WHERE vt.expiryDate < :currentDate")
    void deleteExpiredTokens(@Param("currentDate") LocalDateTime currentDate);
}