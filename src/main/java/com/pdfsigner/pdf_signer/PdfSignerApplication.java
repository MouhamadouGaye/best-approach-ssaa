package com.pdfsigner.pdf_signer;

import java.security.SecureRandom;
import java.util.Set;
import com.pdfsigner.pdf_signer.model.Role;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

// @SpringBootApplication
// @EntityScan("com.pdfsigner.pdf_signer.model")
// @EnableJpaRepositories("com.pdfsigner.pdf_signer.repository")
// @ComponentScan("com.pdfsigner.pdf_signer")

@SpringBootApplication
@Slf4j
public class PdfSignerApplication {

	public static void main(String[] args) {
		SpringApplication.run(PdfSignerApplication.class, args);

	}

	@Bean
	CommandLineRunner initUsers(UserRepository userRepo, PasswordEncoder encoder) {
		return args -> {
			if (userRepo.count() == 0) {
				User admin = new User();
				admin.setEmail("admin@example.com");
				admin.setPassword(encoder.encode("password"));
				admin.setRoles(Set.of(Role.ADMIN));
				userRepo.save(admin);
			}
		};
	}
}
