package com.pdfsigner.pdf_signer.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.pdfsigner.pdf_signer.model.Signature;
import com.pdfsigner.pdf_signer.model.User;

import java.util.List;

@Repository
public interface SignatureRepository extends JpaRepository<Signature, Long> {
    List<Signature> findByUser(User user);

    List<Signature> findByUserOrderByCreatedAtDesc(User user);
}
