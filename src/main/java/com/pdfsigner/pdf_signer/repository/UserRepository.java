package com.pdfsigner.pdf_signer.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.pdfsigner.pdf_signer.model.User;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    @EntityGraph(attributePaths = "roles")
    @Query("SELECT u FROM User u LEFT JOIN FETCH u.roles WHERE u.email = :email")
    Optional<User> findByEmailWithRoles(String email);

    // @EntityGraph(attributePaths = "roles")
    // @Query("SELECT u FROM User u LEFT JOIN FETCH u.roles WHERE u.email = :email")
    // Optional<User> findByEmailWithRoles(@Param("email") String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);
}