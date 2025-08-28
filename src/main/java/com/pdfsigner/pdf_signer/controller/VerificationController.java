package com.pdfsigner.pdf_signer.controller;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.pdfsigner.pdf_signer.dto.ApiResponse;
import com.pdfsigner.pdf_signer.dto.PasswordResetRequest;
import com.pdfsigner.pdf_signer.dto.ResetPasswordRequest;
import com.pdfsigner.pdf_signer.excetion.InvalidTokenException;
import com.pdfsigner.pdf_signer.excetion.UserNotFoundException;
import com.pdfsigner.pdf_signer.model.TokenType;
import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.model.VerificationToken;
import com.pdfsigner.pdf_signer.repository.UserRepository;
import com.pdfsigner.pdf_signer.repository.VerificationTokenRepository;
import com.pdfsigner.pdf_signer.service.AuthService;
import com.pdfsigner.pdf_signer.service.EmailService;
import com.pdfsigner.pdf_signer.service.TokenService;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/verification")
@RequiredArgsConstructor
public class VerificationController {

    private final AuthService authService;
    private final TokenService tokenService;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final VerificationTokenRepository tokenRepository;

    // CHANGE THIS: Make it a GET endpoint for browser links
    @GetMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestParam String token) {
        try {
            authService.verifyEmail(token);
            return ResponseEntity.ok()
                    .contentType(MediaType.TEXT_HTML)
                    .body(createSuccessHtmlPage("Email verified successfully!"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .contentType(MediaType.TEXT_HTML)
                    .body(createErrorHtmlPage("Email verification failed: " + e.getMessage()));
        }

    }

    // Keep your existing POST endpoint for API clients
    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponse> verifyEmailApi(@RequestParam String token) {
        authService.verifyEmail(token);
        return ResponseEntity.ok(new ApiResponse(true, "Email verified successfully"));
    }

    // // GET endpoint for browser access - shows HTML form
    // @GetMapping("/reset-password")
    // public ResponseEntity<String> showResetPasswordForm(@RequestParam String
    // token) {
    // try {
    // // Validate token first
    // VerificationToken resetToken = tokenService.validateToken(token,
    // TokenType.PASSWORD_RESET);

    // // Return HTML form
    // return ResponseEntity.ok()
    // .contentType(MediaType.TEXT_HTML)
    // .body(createResetPasswordForm(token));

    // } catch (Exception e) {
    // return ResponseEntity.status(HttpStatus.BAD_REQUEST)
    // .contentType(MediaType.TEXT_HTML)
    // .body(createErrorPage("Invalid or expired reset token: " + e.getMessage()));
    // }
    // }

    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse> resendVerificationEmail(@RequestParam String email) {
        VerificationToken newToken = tokenService.resendVerificationToken(email);
        User user = newToken.getUser();
        emailService.sendVerificationEmail(user, newToken.getToken());

        return ResponseEntity.ok(new ApiResponse(true, "Verification email resent successfully"));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse> forgotPassword(@RequestParam String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User is not found"));

        VerificationToken resetToken = tokenService.createPasswordResetToken(user);
        emailService.sendPasswordResetEmail(user, resetToken.getToken());

        return ResponseEntity.ok(new ApiResponse(true, "Password reset email sent"));
    }

    // @PostMapping("/reset-password")
    // public ResponseEntity<ApiResponse> resetPassword(
    // @RequestParam String token,
    // @Valid @RequestBody ResetPasswordRequest request) {

    // VerificationToken resetToken = tokenService.validateToken(token,
    // TokenType.PASSWORD_RESET);
    // User user = resetToken.getUser();

    // user.setPassword(passwordEncoder.encode(request.getNewPassword()));
    // userRepository.save(user);

    // tokenService.useToken(resetToken);

    // return ResponseEntity.ok(new ApiResponse(true, "Password reset
    // successfully"));
    // }

    // @GetMapping("/reset-password")
    // public ResponseEntity<String> showResetPasswordForm(@RequestParam String
    // token) {
    // try {
    // log.info("Original token parameter: {}", token);

    // // Proper URL decoding
    // String decodedToken = URLDecoder.decode(token,
    // StandardCharsets.UTF_8.toString());
    // log.info("Decoded token: {}", decodedToken);

    // // Remove any URL encoding artifacts
    // String cleanToken = decodedToken.replaceAll("[^a-zA-Z0-9_\\-]", "");
    // log.info("Cleaned token: {}", cleanToken);

    // if (cleanToken.isEmpty()) {
    // throw new InvalidTokenException("Empty token after cleaning");
    // }

    // // Validate the cleaned token
    // VerificationToken resetToken = tokenService.validateToken(cleanToken,
    // TokenType.PASSWORD_RESET);

    // return ResponseEntity.ok()
    // .contentType(MediaType.TEXT_HTML)
    // .body(createResetPasswordForm(cleanToken));

    // } catch (Exception e) {
    // log.error("Token validation failed", e);
    // return createErrorResponse("Invalid reset link. The link may have expired or
    // been used already.");
    // }
    // }

    // // POST - Processes the form submission
    // @PostMapping("/reset-password")
    // public ResponseEntity<ApiResponse> processResetPassword(
    // @RequestParam String token,
    // @Valid @RequestBody ResetPasswordRequest request) {

    // try {
    // request.validate(); // Validate password confirmation

    // VerificationToken resetToken = tokenService.validateToken(token,
    // TokenType.PASSWORD_RESET);
    // User user = resetToken.getUser();

    // user.setPassword(passwordEncoder.encode(request.getNewPassword()));
    // userRepository.save(user);

    // tokenService.useToken(resetToken);

    // return ResponseEntity.ok(new ApiResponse(true, "Password reset
    // successfully"));

    // } catch (Exception e) {
    // return ResponseEntity.status(HttpStatus.BAD_REQUEST)
    // .body(new ApiResponse(false, "Failed to reset password: " + e.getMessage()));
    // }
    // }

    // @GetMapping("/reset-password")
    // public ResponseEntity<String> showResetPasswordForm(@RequestParam String
    // token, HttpServletResponse response) {
    // try {
    // response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    // response.setHeader("Pragma", "no-cache");
    // response.setHeader("Expires", "0");

    // String decodedToken = URLDecoder.decode(token, StandardCharsets.UTF_8);
    // String cleanToken = decodedToken.trim();

    // log.info("Processing reset password request for token: {}", cleanToken);

    // // Validate token without throwing immediate exceptions
    // try {
    // VerificationToken resetToken = tokenService.validateToken(cleanToken,
    // TokenType.PASSWORD_RESET);
    // if (resetToken.isUsed() || resetToken.isExpired()) {
    // throw new InvalidTokenException("Token already used or expired");
    // }
    // } catch (Exception e) {
    // log.warn("Token validation failed: {}", e.getMessage());
    // return createErrorResponse("This reset link is invalid or has expired. Please
    // request a new one.");
    // }

    // return ResponseEntity.ok()
    // .contentType(MediaType.TEXT_HTML)
    // .body(createModernResetPasswordForm(cleanToken));

    // } catch (Exception e) {
    // log.error("Error showing reset password form", e);
    // return createErrorResponse("Invalid reset link. Please try again.");
    // }
    // }

    // @PostMapping("/reset-password")
    // public ResponseEntity<Map<String, String>> handlePasswordReset(
    // @RequestParam String token,
    // @RequestBody PasswordResetRequest request) {

    // Map<String, String> response = new HashMap<>();

    // try {
    // String decodedToken = URLDecoder.decode(token, StandardCharsets.UTF_8);
    // String cleanToken = decodedToken.trim();

    // if (!request.getNewPassword().equals(request.getConfirmPassword())) {
    // response.put("message", "Passwords do not match");
    // return ResponseEntity.badRequest().body(response);
    // }

    // if (request.getNewPassword().length() < 8) {
    // response.put("message", "Password must be at least 8 characters long");
    // return ResponseEntity.badRequest().body(response);
    // }

    // authService.resetPassword(cleanToken, request.getNewPassword());

    // response.put("message", "Password reset successfully! You can now login with
    // your new password.");
    // response.put("redirect", "/login");

    // return ResponseEntity.ok(response);

    // } catch (InvalidTokenException e) {
    // response.put("message", "Invalid or expired reset link");
    // return ResponseEntity.badRequest().body(response);
    // } catch (Exception e) {
    // log.error("Password reset failed", e);
    // response.put("message", "Failed to reset password. Please try again.");
    // return ResponseEntity.internalServerError().body(response);
    // }
    // }

    // private String createModernResetPasswordForm(String token) {
    // String template = """
    // <!DOCTYPE html>
    // <html lang="en">
    // <head>
    // <meta charset="UTF-8">
    // <meta name="viewport" content="width=device-width, initial-scale=1.0">
    // <title>Reset Password - PDF Signer</title>
    // <link
    // href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css"
    // rel="stylesheet">
    // <link
    // href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"
    // rel="stylesheet">
    // <style>
    // .password-strength { height: 4px; transition: all 0.3s ease; }
    // .shake { animation: shake 0.5s; }
    // @keyframes shake { 0%, 100% { transform: translateX(0); } 25% { transform:
    // translateX(-5px); } 75% { transform: translateX(5px); } }
    // </style>
    // </head>
    // <body class="bg-gradient-to-br from-blue-50 to-indigo-100 min-h-screen flex
    // items-center justify-center p-4">
    // <div class="bg-white rounded-2xl shadow-xl p-8 w-full max-w-md">
    // <div class="text-center mb-8">
    // <div class="w-16 h-16 bg-blue-100 rounded-full flex items-center
    // justify-center mx-auto mb-4">
    // <i class="fas fa-lock text-blue-600 text-2xl"></i>
    // </div>
    // <h1 class="text-2xl font-bold text-gray-800 mb-2">Reset Your Password</h1>
    // <p class="text-gray-600">Create a new secure password for your account</p>
    // </div>
    // <form id="resetForm" class="space-y-6">
    // <input type="hidden" id="token" value="{0}">
    // """; // Continue with the rest of your HTML

    // // Use MessageFormat to safely insert the token
    // return java.text.MessageFormat.format(template, token) +
    // // Add the rest of your HTML here using string concatenation
    // """
    // <!-- Rest of your form fields -->
    // <div class="form-group">
    // <label for="newPassword" class="block text-sm font-medium text-gray-700
    // mb-2">
    // New Password
    // </label>
    // <div class="relative">
    // <input
    // type="password"
    // id="newPassword"
    // required
    // minlength="8"
    // class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2
    // focus:ring-blue-500 focus:border-transparent transition-all duration-200"
    // placeholder="Enter your new password"
    // >
    // <button type="button" onclick="togglePassword('newPassword')" class="absolute
    // right-3 top-3 text-gray-400 hover:text-gray-600">
    // <i class="fas fa-eye"></i>
    // </button>
    // </div>
    // <div class="mt-2 grid grid-cols-4 gap-1">
    // <div id="strength-1" class="password-strength bg-gray-200 rounded"></div>
    // <div id="strength-2" class="password-strength bg-gray-200 rounded"></div>
    // <div id="strength-3" class="password-strength bg-gray-200 rounded"></div>
    // <div id="strength-4" class="password-strength bg-gray-200 rounded"></div>
    // </div>
    // </div>
    // <!-- Continue with the rest of your HTML -->
    // </form>
    // </div>
    // </body>
    // </html>
    // """;
    // }

    @GetMapping("/reset-password")
    public ResponseEntity<String> showResetPasswordForm(@RequestParam String token, HttpServletResponse response) {
        try {
            response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
            response.setHeader("Pragma", "no-cache");
            response.setHeader("Expires", "0");

            log.info("Original token parameter: {}", token);

            // Proper URL decoding with error handling
            String decodedToken;
            try {
                decodedToken = URLDecoder.decode(token, StandardCharsets.UTF_8.toString());
            } catch (UnsupportedEncodingException e) {
                decodedToken = URLDecoder.decode(token, StandardCharsets.ISO_8859_1.toString());
            }

            log.info("Decoded token: {}", decodedToken);

            // Clean the token - remove any non-alphanumeric characters except hyphens and
            // underscores
            String cleanToken = decodedToken.replaceAll("[^a-zA-Z0-9_\\-]", "");
            log.info("Cleaned token: {}", cleanToken);

            if (cleanToken.isEmpty()) {
                throw new InvalidTokenException("Empty token after cleaning");
            }

            // Validate the token
            try {
                VerificationToken resetToken = tokenService.validateToken(cleanToken, TokenType.PASSWORD_RESET);
                if (resetToken.isUsed() || resetToken.isExpired()) {
                    throw new InvalidTokenException("Token already used or expired");
                }
            } catch (Exception e) {
                log.warn("Token validation failed: {}", e.getMessage());
                return createErrorResponse("This reset link is invalid or has expired. Please request a new one.");
            }

            return ResponseEntity.ok()
                    .contentType(MediaType.TEXT_HTML)
                    .body(createModernResetPasswordForm(cleanToken));

        } catch (Exception e) {
            log.error("Error showing reset password form", e);
            return createErrorResponse("Invalid reset link. Please try again.");
        }
    }

    private String createModernResetPasswordForm(String token) {
        // Use simple string concatenation to avoid formatting issues
        StringBuilder html = new StringBuilder();

        html.append("<!DOCTYPE html>")
                .append("<html lang=\"en\">")
                .append("<head>")
                .append("    <meta charset=\"UTF-8\">")
                .append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">")
                .append("    <title>Reset Password - PDF Signer</title>")
                .append("    <link href=\"https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css\" rel=\"stylesheet\">")
                .append("    <link href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css\" rel=\"stylesheet\">")
                .append("    <style>")
                .append("        .password-strength { height: 4px; transition: all 0.3s ease; }")
                .append("        .shake { animation: shake 0.5s; }")
                .append("        @keyframes shake { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-5px); } 75% { transform: translateX(5px); } }")
                .append("    </style>")
                .append("</head>")
                .append("<body class=\"bg-gradient-to-br from-blue-50 to-indigo-100 min-h-screen flex items-center justify-center p-4\">")
                .append("    <div class=\"bg-white rounded-2xl shadow-xl p-8 w-full max-w-md\">")
                .append("        <div class=\"text-center mb-8\">")
                .append("            <div class=\"w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4\">")
                .append("                <i class=\"fas fa-lock text-blue-600 text-2xl\"></i>")
                .append("            </div>")
                .append("            <h1 class=\"text-2xl font-bold text-gray-800 mb-2\">Reset Your Password</h1>")
                .append("            <p class=\"text-gray-600\">Create a new secure password for your account</p>")
                .append("        </div>")
                .append("        <form id=\"resetForm\" class=\"space-y-6\">")
                .append("            <input type=\"hidden\" id=\"token\" value=\"").append(token).append("\">")
                .append("            <div>")
                .append("                <label for=\"newPassword\" class=\"block text-sm font-medium text-gray-700 mb-2\">")
                .append("                    New Password")
                .append("                </label>")
                .append("                <div class=\"relative\">")
                .append("                    <input type=\"password\" id=\"newPassword\" required minlength=\"8\"")
                .append("                           class=\"w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200\"")
                .append("                           placeholder=\"Enter your new password\">")
                .append("                    <button type=\"button\" onclick=\"togglePassword('newPassword')\" class=\"absolute right-3 top-3 text-gray-400 hover:text-gray-600\">")
                .append("                        <i class=\"fas fa-eye\"></i>")
                .append("                    </button>")
                .append("                </div>")
                .append("                <div class=\"mt-2 grid grid-cols-4 gap-1\">")
                .append("                    <div id=\"strength-1\" class=\"password-strength bg-gray-200 rounded\"></div>")
                .append("                    <div id=\"strength-2\" class=\"password-strength bg-gray-200 rounded\"></div>")
                .append("                    <div id=\"strength-3\" class=\"password-strength bg-gray-200 rounded\"></div>")
                .append("                    <div id=\"strength-4\" class=\"password-strength bg-gray-200 rounded\"></div>")
                .append("                </div>")
                .append("            </div>")
                .append("            <div>")
                .append("                <label for=\"confirmPassword\" class=\"block text-sm font-medium text-gray-700 mb-2\">")
                .append("                    Confirm Password")
                .append("                </label>")
                .append("                <div class=\"relative\">")
                .append("                    <input type=\"password\" id=\"confirmPassword\" required")
                .append("                           class=\"w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200\"")
                .append("                           placeholder=\"Confirm your new password\">")
                .append("                    <button type=\"button\" onclick=\"togglePassword('confirmPassword')\" class=\"absolute right-3 top-3 text-gray-400 hover:text-gray-600\">")
                .append("                        <i class=\"fas fa-eye\"></i>")
                .append("                    </button>")
                .append("                </div>")
                .append("            </div>")
                .append("            <button type=\"submit\" id=\"submitBtn\"")
                .append("                    class=\"w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition-all duration-200 transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2\">")
                .append("                <span id=\"btnText\">Reset Password</span>")
                .append("                <div id=\"spinner\" class=\"hidden inline-flex items-center\">")
                .append("                    <div class=\"animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2\"></div>")
                .append("                    Processing...")
                .append("                </div>")
                .append("            </button>")
                .append("        </form>")
                .append("        <div id=\"message\" class=\"mt-6 p-4 rounded-lg hidden\"></div>")
                .append("        <div class=\"mt-6 text-center\">")
                .append("            <a href=\"/login\" class=\"text-blue-600 hover:text-blue-800 text-sm font-medium transition-colors duration-200\">")
                .append("                <i class=\"fas fa-arrow-left mr-2\"></i>Back to Login")
                .append("            </a>")
                .append("        </div>")
                .append("    </div>")
                .append("    <script>")
                .append("        const token = '").append(token).append("';")
                .append("        function togglePassword(inputId) {")
                .append("            const input = document.getElementById(inputId);")
                .append("            const icon = input.nextElementSibling.querySelector('i');")
                .append("            if (input.type === 'password') {")
                .append("                input.type = 'text';")
                .append("                icon.className = 'fas fa-eye-slash';")
                .append("            } else {")
                .append("                input.type = 'password';")
                .append("                icon.className = 'fas fa-eye';")
                .append("            }")
                .append("        }")
                .append("        function checkPasswordStrength(password) {")
                .append("            let strength = 0;")
                .append("            if (password.length >= 8) strength++;")
                .append("            if (/[A-Z]/.test(password)) strength++;")
                .append("            if (/[0-9]/.test(password)) strength++;")
                .append("            if (/[^A-Za-z0-9]/.test(password)) strength++;")
                .append("            for (let i = 1; i <= 4; i++) {")
                .append("                const bar = document.getElementById('strength-' + i);")
                .append("                bar.className = 'password-strength rounded ' + ")
                .append("                    (i <= strength ? getStrengthColor(strength) : 'bg-gray-200');")
                .append("            }")
                .append("        }")
                .append("        function getStrengthColor(strength) {")
                .append("            const colors = ['bg-red-500', 'bg-orange-500', 'bg-yellow-500', 'bg-green-500'];")
                .append("            return colors[strength - 1] || 'bg-gray-200';")
                .append("        }")
                .append("        document.getElementById('newPassword').addEventListener('input', (e) => {")
                .append("            checkPasswordStrength(e.target.value);")
                .append("        });")
                .append("        document.getElementById('resetForm').addEventListener('submit', async function(e) {")
                .append("            e.preventDefault();")
                .append("            const newPassword = document.getElementById('newPassword').value;")
                .append("            const confirmPassword = document.getElementById('confirmPassword').value;")
                .append("            const messageDiv = document.getElementById('message');")
                .append("            const submitBtn = document.getElementById('submitBtn');")
                .append("            const btnText = document.getElementById('btnText');")
                .append("            const spinner = document.getElementById('spinner');")
                .append("            messageDiv.className = 'mt-6 p-4 rounded-lg hidden';")
                .append("            messageDiv.textContent = '';")
                .append("            if (newPassword !== confirmPassword) {")
                .append("                messageDiv.className = 'mt-6 p-4 rounded-lg bg-red-100 text-red-700 border border-red-200';")
                .append("                messageDiv.textContent = 'Passwords do not match';")
                .append("                document.getElementById('confirmPassword').classList.add('shake');")
                .append("                setTimeout(() => document.getElementById('confirmPassword').classList.remove('shake'), 500);")
                .append("                return;")
                .append("            }")
                .append("            if (newPassword.length < 8) {")
                .append("                messageDiv.className = 'mt-6 p-4 rounded-lg bg-red-100 text-red-700 border border-red-200';")
                .append("                messageDiv.textContent = 'Password must be at least 8 characters long';")
                .append("                return;")
                .append("            }")
                .append("            btnText.classList.add('hidden');")
                .append("            spinner.classList.remove('hidden');")
                .append("            submitBtn.disabled = true;")
                .append("            try {")
                .append("                const response = await fetch('/api/verification/reset-password?token=' + encodeURIComponent(token), {")
                .append("                    method: 'POST',")
                .append("                    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },")
                .append("                    body: JSON.stringify({ newPassword: newPassword, confirmPassword: confirmPassword })")
                .append("                });")
                .append("                const data = await response.json();")
                .append("                if (response.ok) {")
                .append("                    messageDiv.className = 'mt-6 p-4 rounded-lg bg-green-100 text-green-700 border border-green-200';")
                .append("                    messageDiv.innerHTML = '<div class=\"flex items-center\"><i class=\"fas fa-check-circle mr-2\"></i>' + data.message + '</div>';")
                .append("                    if (data.redirect) {")
                .append("                        setTimeout(() => { window.location.href = data.redirect; }, 2000);")
                .append("                    }")
                .append("                } else {")
                .append("                    messageDiv.className = 'mt-6 p-4 rounded-lg bg-red-100 text-red-700 border border-red-200';")
                .append("                    messageDiv.innerHTML = '<div class=\"flex items-center\"><i class=\"fas fa-exclamation-circle mr-2\"></i>' + data.message + '</div>';")
                .append("                }")
                .append("            } catch (error) {")
                .append("                messageDiv.className = 'mt-6 p-4 rounded-lg bg-red-100 text-red-700 border border-red-200';")
                .append("                messageDiv.innerHTML = '<div class=\"flex items-center\"><i class=\"fas fa-exclamation-circle mr-2\"></i>Network error. Please check your connection and try again.</div>';")
                .append("            } finally {")
                .append("                btnText.classList.remove('hidden');")
                .append("                spinner.classList.add('hidden');")
                .append("                submitBtn.disabled = false;")
                .append("            }")
                .append("        });")
                .append("        const style = document.createElement('style');")
                .append("        style.textContent = `")
                .append("            .shake { animation: shake 0.5s; }")
                .append("            @keyframes shake { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-5px); } 75% { transform: translateX(5px); } }")
                .append("        `;")
                .append("        document.head.appendChild(style);")
                .append("    </script>")
                .append("</body>")
                .append("</html>");

        return html.toString();
    }

    private ResponseEntity<String> createErrorResponse(String message) {
        String errorPage = "<!DOCTYPE html>" +
                "<html>" +
                "<head>" +
                "    <title>Error - PDF Signer</title>" +
                "    <link href=\"https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css\" rel=\"stylesheet\">"
                +
                "</head>" +
                "<body class=\"bg-gray-100 min-h-screen flex items-center justify-center\">" +
                "    <div class=\"bg-white p-8 rounded-lg shadow-md max-w-md w-full text-center\">" +
                "        <div class=\"text-red-500 text-6xl mb-4\">⚠️</div>" +
                "        <h1 class=\"text-2xl font-bold text-gray-800 mb-4\">Oops! Something went wrong</h1>" +
                "        <p class=\"text-gray-600 mb-6\">" + message + "</p>" +
                "        <a href=\"/forgot-password\" class=\"bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors\">"
                +
                "            Request New Reset Link" +
                "        </a>" +
                "        <div class=\"mt-4\">" +
                "            <a href=\"/login\" class=\"text-blue-600 hover:text-blue-800 text-sm\">Back to Login</a>" +
                "        </div>" +
                "    </div>" +
                "</body>" +
                "</html>";

        return ResponseEntity.badRequest()
                .contentType(MediaType.TEXT_HTML)
                .body(errorPage);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> handlePasswordReset(
            @RequestParam String token,
            @RequestBody PasswordResetRequest request) {

        Map<String, String> response = new HashMap<>();

        try {
            // Decode and clean the token
            String decodedToken = URLDecoder.decode(token, StandardCharsets.UTF_8);
            String cleanToken = decodedToken.replaceAll("[^a-zA-Z0-9_\\-]", "");

            if (cleanToken.isEmpty()) {
                response.put("message", "Invalid token");
                return ResponseEntity.badRequest().body(response);
            }

            // Rest of your password reset logic...
            if (!request.getNewPassword().equals(request.getConfirmPassword())) {
                response.put("message", "Passwords do not match");
                return ResponseEntity.badRequest().body(response);
            }

            authService.resetPassword(cleanToken, request.getNewPassword());

            response.put("message", "Password reset successfully! You can now login with your new password.");
            response.put("redirect", "/login");

            return ResponseEntity.ok(response);

        } catch (InvalidTokenException e) {
            response.put("message", "Invalid or expired reset link");
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            log.error("Password reset failed", e);
            response.put("message", "Failed to reset password. Please try again.");
            return ResponseEntity.internalServerError().body(response);
        }
    }

    // private String createModernResetPasswordForm(String token) {
    // return """
    // <!DOCTYPE html>
    // <html lang="en">
    // <head>
    // <meta charset="UTF-8">
    // <meta name="viewport" content="width=device-width, initial-scale=1.0">
    // <title>Reset Password - PDF Signer</title>
    // <link
    // href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css"
    // rel="stylesheet">
    // <link
    // href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"
    // rel="stylesheet">
    // <style>
    // .password-strength {
    // height: 4px;
    // transition: all 0.3s ease;
    // }
    // .shake {
    // animation: shake 0.5s;
    // }
    // @keyframes shake {
    // 0%, 100% { transform: translateX(0); }
    // 25% { transform: translateX(-5px); }
    // 75% { transform: translateX(5px); }
    // }
    // </style>
    // </head>
    // <body class="bg-gradient-to-br from-blue-50 to-indigo-100 min-h-screen flex
    // items-center justify-center p-4">
    // <div class="bg-white rounded-2xl shadow-xl p-8 w-full max-w-md">
    // <div class="text-center mb-8">
    // <div class="w-16 h-16 bg-blue-100 rounded-full flex items-center
    // justify-center mx-auto mb-4">
    // <i class="fas fa-lock text-blue-600 text-2xl"></i>
    // </div>
    // <h1 class="text-2xl font-bold text-gray-800 mb-2">Reset Your Password</h1>
    // <p class="text-gray-600">Create a new secure password for your account</p>
    // </div>

    // <form id="resetForm" class="space-y-6">
    // <input type="hidden" id="token" value="%s">

    // <div>
    // <label for="newPassword" class="block text-sm font-medium text-gray-700
    // mb-2">
    // New Password
    // </label>
    // <div class="relative">
    // <input
    // type="password"
    // id="newPassword"
    // required
    // minlength="8"
    // class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2
    // focus:ring-blue-500 focus:border-transparent transition-all duration-200"
    // placeholder="Enter your new password"
    // >
    // <button type="button" onclick="togglePassword('newPassword')" class="absolute
    // right-3 top-3 text-gray-400 hover:text-gray-600">
    // <i class="fas fa-eye"></i>
    // </button>
    // </div>
    // <div class="mt-2 grid grid-cols-4 gap-1">
    // <div id="strength-1" class="password-strength bg-gray-200 rounded"></div>
    // <div id="strength-2" class="password-strength bg-gray-200 rounded"></div>
    // <div id="strength-3" class="password-strength bg-gray-200 rounded"></div>
    // <div id="strength-4" class="password-strength bg-gray-200 rounded"></div>
    // </div>
    // </div>

    // <div>
    // <label for="confirmPassword" class="block text-sm font-medium text-gray-700
    // mb-2">
    // Confirm Password
    // </label>
    // <div class="relative">
    // <input
    // type="password"
    // id="confirmPassword"
    // required
    // class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2
    // focus:ring-blue-500 focus:border-transparent transition-all duration-200"
    // placeholder="Confirm your new password"
    // >
    // <button type="button" onclick="togglePassword('confirmPassword')"
    // class="absolute right-3 top-3 text-gray-400 hover:text-gray-600">
    // <i class="fas fa-eye"></i>
    // </button>
    // </div>
    // </div>

    // <button
    // type="submit"
    // id="submitBtn"
    // class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4
    // rounded-lg transition-all duration-200 transform hover:scale-105
    // focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
    // >
    // <span id="btnText">Reset Password</span>
    // <div id="spinner" class="hidden inline-flex items-center">
    // <div class="animate-spin rounded-full h-4 w-4 border-b-2 border-white
    // mr-2"></div>
    // Processing...
    // </div>
    // </button>
    // </form>

    // <div id="message" class="mt-6 p-4 rounded-lg hidden"></div>

    // <div class="mt-6 text-center">
    // <a href="/login" class="text-blue-600 hover:text-blue-800 text-sm font-medium
    // transition-colors duration-200">
    // <i class="fas fa-arrow-left mr-2"></i>Back to Login
    // </a>
    // </div>
    // </div>

    // <script>
    // const token = document.getElementById('token').value;

    // function togglePassword(inputId) {
    // const input = document.getElementById(inputId);
    // const icon = input.nextElementSibling.querySelector('i');
    // if (input.type === 'password') {
    // input.type = 'text';
    // icon.className = 'fas fa-eye-slash';
    // } else {
    // input.type = 'password';
    // icon.className = 'fas fa-eye';
    // }
    // }

    // function checkPasswordStrength(password) {
    // let strength = 0;
    // if (password.length >= 8) strength++;
    // if (/[A-Z]/.test(password)) strength++;
    // if (/[0-9]/.test(password)) strength++;
    // if (/[^A-Za-z0-9]/.test(password)) strength++;

    // // Update strength meter
    // for (let i = 1; i <= 4; i++) {
    // const bar = document.getElementById('strength-' + i);
    // bar.className = 'password-strength rounded ' +
    // (i <= strength ? getStrengthColor(strength) : 'bg-gray-200');
    // }
    // }

    // function getStrengthColor(strength) {
    // const colors = ['bg-red-500', 'bg-orange-500', 'bg-yellow-500',
    // 'bg-green-500'];
    // return colors[strength - 1] || 'bg-gray-200';
    // }

    // document.getElementById('newPassword').addEventListener('input', (e) => {
    // checkPasswordStrength(e.target.value);
    // });

    // document.getElementById('resetForm').addEventListener('submit', async
    // function(e) {
    // e.preventDefault();

    // const newPassword = document.getElementById('newPassword').value;
    // const confirmPassword = document.getElementById('confirmPassword').value;
    // const messageDiv = document.getElementById('message');
    // const submitBtn = document.getElementById('submitBtn');
    // const btnText = document.getElementById('btnText');
    // const spinner = document.getElementById('spinner');

    // // Reset message
    // messageDiv.className = 'mt-6 p-4 rounded-lg hidden';
    // messageDiv.textContent = '';

    // // Validate passwords
    // if (newPassword !== confirmPassword) {
    // messageDiv.className = 'mt-6 p-4 rounded-lg bg-red-100 text-red-700 border
    // border-red-200';
    // messageDiv.textContent = 'Passwords do not match';
    // document.getElementById('confirmPassword').classList.add('shake');
    // setTimeout(() =>
    // document.getElementById('confirmPassword').classList.remove('shake'), 500);
    // return;
    // }

    // if (newPassword.length < 8) {
    // messageDiv.className = 'mt-6 p-4 rounded-lg bg-red-100 text-red-700 border
    // border-red-200';
    // messageDiv.textContent = 'Password must be at least 8 characters long';
    // return;
    // }

    // // Show loading state
    // btnText.classList.add('hidden');
    // spinner.classList.remove('hidden');
    // submitBtn.disabled = true;

    // try {
    // const response = await fetch('/api/verification/reset-password?token=' +
    // encodeURIComponent(token), {
    // method: 'POST',
    // headers: {
    // 'Content-Type': 'application/json',
    // 'Accept': 'application/json'
    // },
    // body: JSON.stringify({
    // newPassword: newPassword,
    // confirmPassword: confirmPassword
    // })
    // });

    // const data = await response.json();

    // if (response.ok) {
    // messageDiv.className = 'mt-6 p-4 rounded-lg bg-green-100 text-green-700
    // border border-green-200';
    // messageDiv.innerHTML = `
    // <div class="flex items-center">
    // <i class="fas fa-check-circle mr-2"></i>
    // ${data.message}
    // </div>
    // `;

    // if (data.redirect) {
    // setTimeout(() => {
    // window.location.href = data.redirect;
    // }, 2000);
    // }
    // } else {
    // messageDiv.className = 'mt-6 p-4 rounded-lg bg-red-100 text-red-700 border
    // border-red-200';
    // messageDiv.innerHTML = `
    // <div class="flex items-center">
    // <i class="fas fa-exclamation-circle mr-2"></i>
    // ${data.message}
    // </div>
    // `;
    // }
    // } catch (error) {
    // messageDiv.className = 'mt-6 p-4 rounded-lg bg-red-100 text-red-700 border
    // border-red-200';
    // messageDiv.innerHTML = `
    // <div class="flex items-center">
    // <i class="fas fa-exclamation-circle mr-2"></i>
    // Network error. Please check your connection and try again.
    // </div>
    // `;
    // } finally {
    // btnText.classList.remove('hidden');
    // spinner.classList.add('hidden');
    // submitBtn.disabled = false;
    // }
    // });

    // // Add shake animation class
    // const style = document.createElement('style');
    // style.textContent = `
    // .shake {
    // animation: shake 0.5s;
    // }
    // @keyframes shake {
    // 0%, 100% { transform: translateX(0); }
    // 25% { transform: translateX(-5px); }
    // 75% { transform: translateX(5px); }
    // }
    // `;
    // document.head.appendChild(style);
    // </script>
    // </body>
    // </html>
    // """
    // .formatted(token);
    // }

    // private ResponseEntity<String> createErrorResponse(String message) {
    // String errorPage = """
    // <!DOCTYPE html>
    // <html>
    // <head>
    // <title>Error - PDF Signer</title>
    // <link
    // href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css"
    // rel="stylesheet">
    // </head>
    // <body class="bg-gray-100 min-h-screen flex items-center justify-center">
    // <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full text-center">
    // <div class="text-red-500 text-6xl mb-4">⚠️</div>
    // <h1 class="text-2xl font-bold text-gray-800 mb-4">Oops! Something went
    // wrong</h1>
    // <p class="text-gray-600 mb-6">%s</p>
    // <a href="/forgot-password" class="bg-blue-600 text-white px-6 py-3 rounded-lg
    // hover:bg-blue-700 transition-colors">
    // Request New Reset Link
    // </a>
    // <div class="mt-4">
    // <a href="/login" class="text-blue-600 hover:text-blue-800 text-sm">Back to
    // Login</a>
    // </div>
    // </div>
    // </body>
    // </html>
    // """
    // .formatted(message);

    // return ResponseEntity.badRequest()
    // .contentType(MediaType.TEXT_HTML)
    // .body(errorPage);
    // }

    // private ResponseEntity<String> createErrorResponse(String message) {
    // return ResponseEntity.status(HttpStatus.BAD_REQUEST)
    // .contentType(MediaType.TEXT_HTML)
    // .body("""
    // <!DOCTYPE html>
    // <html>
    // <head>
    // <title>Password Reset Error</title>
    // <style>
    // body { font-family: Arial, sans-serif; max-width: 500px; margin: 100px auto;
    // padding: 20px; text-align: center; }
    // .error { color: #dc3545; font-size: 18px; margin: 20px 0; }
    // .link { color: #007bff; text-decoration: none; margin: 10px; display:
    // inline-block; }
    // .link:hover { text-decoration: underline; }
    // </style>
    // </head>
    // <body>
    // <div style="font-size: 48px; margin-bottom: 20px;">❌</div>
    // <div class="error">%s</div>
    // <div>
    // <a href="/forgot-password" class="link">Request a new reset link</a>
    // <a href="/login" class="link">Return to login</a>
    // </div>
    // </body>
    // </html>
    // """
    // .formatted(message));
    // }

    // // HTML response for success
    // private String createSuccessHtmlPage(String message) {
    // return """
    // <!DOCTYPE html>
    // <html>
    // <head>
    // <title>Email Verified</title>
    // <style>
    // body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
    // .success { color: #4CAF50; font-size: 24px; }
    // .message { margin: 20px 0; }
    // </style>
    // </head>
    // <body>
    // <div class="success">✅ Email Verified Successfully</div>
    // <div class="message">%s</div>
    // <p>You can now <a href="http://localhost:3000/login">login to your
    // account</a>.</p>
    // </body>
    // </html>
    // """.formatted(message);
    // }

    // // HTML response for error
    // private String createErrorHtmlPage(String message) {
    // return """
    // <!DOCTYPE html>
    // <html>
    // <head>
    // <title>Verification Failed</title>
    // <style>
    // body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
    // .error { color: #f44336; font-size: 24px; }
    // .message { margin: 20px 0; }
    // </style>
    // </head>
    // <body>
    // <div class="error">❌ Verification Failed</div>
    // <div class="message">%s</div>
    // <p>Please try again or <a href="http://localhost:3000/support">contact
    // support</a>.</p>
    // </body>
    // </html>
    // """.formatted(message);
    // }

    // Fixed HTML response for success
    private String createSuccessHtmlPage(String message) {
        return "<!DOCTYPE html>" +
                "<html>" +
                "<head>" +
                " <title>Email Verified</title>" +
                " <style>" +
                " body { font-family: Arial, sans-serif; text-align: center; padding: 50px;}" +
                " .success { color: #4CAF50; font-size: 24px; }" +
                " .message { margin: 20px 0; }" +
                " </style>" +
                "</head>" +
                "<body>" +
                " <div class=\"success\">✅ Email Verified Successfully</div>" +
                " <div class=\"message\">" + message + "</div>" +
                " <p>You can now <a href=\"http://localhost:4200/login\">login to your account</a>.</p>" +
                "</body>" +
                "</html>";
    }

    // Fixed HTML response for error
    private String createErrorHtmlPage(String message) {
        return "<!DOCTYPE html>" +
                "<html>" +
                "<head>" +
                " <title>Verification Failed</title>" +
                " <style>" +
                " body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }" +
                " .error { color: #f44336; font-size: 24px; }" +
                " .message { margin: 20px 0; }" +
                " </style>" +
                "</head>" +
                "<body>" +
                " <div class=\"error\">❌ Verification Failed</div>" +
                " <div class=\"message\">" + message + "</div>" +
                " <p>Please try again or <a href=\"http://localhost:3000/support\">contact support</a>.</p>" +
                "</body>" +
                "</html>";
    }

    // private String createResetPasswordForm(String token) {
    // return """
    // <!DOCTYPE html>
    // <html>
    // <head>
    // <title>Reset Password</title>
    // <style>
    // body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto;
    // padding: 20px; }
    // .form-group { margin-bottom: 15px; }
    // label { display: block; margin-bottom: 5px; }
    // input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius:
    // 4px; }
    // button { background: #007bff; color: white; padding: 10px 15px; border: none;
    // border-radius: 4px; cursor: pointer; }
    // .error { color: red; margin-top: 10px; }
    // .success { color: green; margin-top: 10px; }
    // </style>
    // </head>
    // <body>
    // <h2>Reset Your Password</h2>
    // <form id="resetForm">
    // <input type="hidden" id="token" value="%s">
    // <div class="form-group">
    // <label for="newPassword">New Password:</label>
    // <input type="password" id="newPassword" required minlength="8">
    // </div>
    // <div class="form-group">
    // <label for="confirmPassword">Confirm Password:</label>
    // <input type="password" id="confirmPassword" required>
    // </div>
    // <button type="submit">Reset Password</button>
    // </form>
    // <div id="message" class="error"></div>

    // <script>
    // document.getElementById('resetForm').addEventListener('submit', async
    // function(e) {
    // e.preventDefault();

    // const token = document.getElementById('token').value;
    // const newPassword = document.getElementById('newPassword').value;
    // const confirmPassword = document.getElementById('confirmPassword').value;

    // if (newPassword !== confirmPassword) {
    // document.getElementById('message').textContent = 'Passwords do not match';
    // return;
    // }

    // if (newPassword.length < 8) {
    // document.getElementById('message').textContent = 'Password must be at least 8
    // characters';
    // return;
    // }

    // try {
    // const response = await fetch('/api/verification/reset-password?token=' +
    // token, {
    // method: 'POST',
    // headers: {
    // 'Content-Type': 'application/json'
    // },
    // body: JSON.stringify({
    // newPassword: newPassword,
    // confirmPassword: confirmPassword
    // })
    // });

    // const data = await response.json();

    // if (response.ok) {
    // document.getElementById('message').className = 'success';
    // document.getElementById('message').textContent = data.message;
    // document.getElementById('resetForm').reset();
    // } else {
    // document.getElementById('message').className = 'error';
    // document.getElementById('message').textContent = data.message || 'Error
    // resetting password';
    // }
    // } catch (error) {
    // document.getElementById('message').className = 'error';
    // document.getElementById('message').textContent = 'Network error: ' +
    // error.message;
    // }
    // });
    // </script>
    // </body>
    // </html>
    // """
    // .formatted(token);
    // }

    // private String createResetPasswordForm(String token) {
    // // Escape any % characters in the token
    // String safeToken = token.replace("%", "%%");

    // return """
    // <!DOCTYPE html>
    // <html>
    // <head>
    // <title>Reset Password</title>
    // <style>
    // body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto;
    // padding: 20px; }
    // .form-group { margin-bottom: 15px; }
    // label { display: block; margin-bottom: 5px; font-weight: bold; }
    // input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius:
    // 4px; box-sizing: border-box; }
    // button { background: #007bff; color: white; padding: 12px 20px; border: none;
    // border-radius: 4px; cursor: pointer; width: 100%; }
    // button:hover { background: #0056b3; }
    // button:disabled { background: #ccc; cursor: not-allowed; }
    // .error { color: #dc3545; margin-top: 10px; text-align: center; }
    // .success { color: #28a745; margin-top: 10px; text-align: center; }
    // </style>
    // </head>
    // <body>
    // <h2 style="text-align: center; color: #333;">Reset Your Password</h2>
    // <form id="resetForm">
    // <input type="hidden" id="token" value="%s">
    // <div class="form-group">
    // <label for="newPassword">New Password:</label>
    // <input type="password" id="newPassword" required minlength="8"
    // placeholder="Enter at least 8 characters">
    // </div>
    // <div class="form-group">
    // <label for="confirmPassword">Confirm Password:</label>
    // <input type="password" id="confirmPassword" required
    // placeholder="Confirm your password">
    // </div>
    // <button type="submit">Reset Password</button>
    // </form>
    // <div id="message" class="error"></div>

    // <script>
    // document.getElementById('resetForm').addEventListener('submit', async
    // function(e) {
    // e.preventDefault();

    // const token = document.getElementById('token').value;
    // const newPassword = document.getElementById('newPassword').value;
    // const confirmPassword = document.getElementById('confirmPassword').value;
    // const messageDiv = document.getElementById('message');

    // // Clear previous messages
    // messageDiv.className = 'error';
    // messageDiv.textContent = '';

    // // Validation
    // if (newPassword !== confirmPassword) {
    // messageDiv.textContent = 'Passwords do not match';
    // return;
    // }

    // if (newPassword.length < 8) {
    // messageDiv.textContent = 'Password must be at least 8 characters';
    // return;
    // }

    // // Disable button during request
    // const submitButton = e.target.querySelector('button[type="submit"]');
    // submitButton.disabled = true;
    // submitButton.textContent = 'Resetting...';

    // try {
    // const response = await fetch('/api/verification/reset-password?token=' +
    // encodeURIComponent(token), {
    // method: 'POST',
    // headers: {
    // 'Content-Type': 'application/json',
    // 'Accept': 'application/json'
    // },
    // body: JSON.stringify({
    // newPassword: newPassword,
    // confirmPassword: confirmPassword
    // })
    // });

    // const data = await response.json();

    // if (response.ok) {
    // messageDiv.className = 'success';
    // messageDiv.textContent = data.message || 'Password reset successfully!';
    // document.getElementById('resetForm').reset();

    // // Redirect to login after 3 seconds
    // setTimeout(() => {
    // window.location.href = '/login';
    // }, 3000);
    // } else {
    // messageDiv.textContent = data.message || 'Error resetting password';
    // }
    // } catch (error) {
    // messageDiv.textContent = 'Network error: ' + error.message;
    // } finally {
    // submitButton.disabled = false;
    // submitButton.textContent = 'Reset Password';
    // }
    // });
    // </script>
    // </body>
    // </html>
    // """
    // .formatted(safeToken); // Use the escaped token
    // }

    private String createResetPasswordForm(String token) {
        // Use simple concatenation to avoid formatting issues
        return "<!DOCTYPE html>" +
                "<html>" +
                "<head>" +
                "    <title>Reset Password</title>" +
                "    <style>" +
                "        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }" +
                "        .form-group { margin-bottom: 15px; }" +
                "        label { display: block; margin-bottom: 5px; font-weight: bold; }" +
                "        input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }" +
                "        button { background: #007bff; color: white; padding: 12px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }"
                +
                "        .error { color: #dc3545; margin-top: 10px; }" +
                "        .success { color: #28a745; margin-top: 10px; }" +
                "    </style>" +
                "</head>" +
                "<body>" +
                "    <h2 style='text-align: center;'>Reset Your Password</h2>" +
                "    <form id='resetForm'>" +
                "        <input type='hidden' id='token' value='" + token + "'>" +
                "        <div class='form-group'>" +
                "            <label for='newPassword'>New Password:</label>" +
                "            <input type='password' id='newPassword' required minlength='8'>" +
                "        </div>" +
                "        <div class='form-group'>" +
                "            <label for='confirmPassword'>Confirm Password:</label>" +
                "            <input type='password' id='confirmPassword' required>" +
                "        </div>" +
                "        <button type='submit'>Reset Password</button>" +
                "    </form>" +
                "    <div id='message' class='error'></div>" +
                "    <script>" +
                "        document.getElementById('resetForm').addEventListener('submit', async function(e) {" +
                "            e.preventDefault();" +
                "            " +
                "            const token = document.getElementById('token').value;" +
                "            const newPassword = document.getElementById('newPassword').value;" +
                "            const confirmPassword = document.getElementById('confirmPassword').value;" +
                "            " +
                "            if (newPassword !== confirmPassword) {" +
                "                document.getElementById('message').textContent = 'Passwords do not match';" +
                "                return;" +
                "            }" +
                "            " +
                "            try {" +
                "                const response = await fetch('/api/verification/reset-password?token=' + token, {" +
                "                    method: 'POST'," +
                "                    headers: { 'Content-Type': 'application/json' }," +
                "                    body: JSON.stringify({ newPassword, confirmPassword })" +
                "                });" +
                "                " +
                "                const data = await response.json();" +
                "                " +
                "                if (response.ok) {" +
                "                    document.getElementById('message').className = 'success';" +
                "                    document.getElementById('message').textContent = data.message;" +
                "                } else {" +
                "                    document.getElementById('message').textContent = data.message;" +
                "                }" +
                "            } catch (error) {" +
                "                document.getElementById('message').textContent = 'Network error';" +
                "            }" +
                "        });" +
                "    </script>" +
                "</body>" +
                "</html>";
    }

    // private String createErrorPage(String message) {
    // return """
    // <!DOCTYPE html>
    // <html>
    // <head>
    // <title>Error</title>
    // <style>
    // body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto;
    // padding: 20px; }
    // .error { color: red; }
    // </style>
    // </head>
    // <body>
    // <h2>Password Reset Error</h2>
    // <div class="error">%s</div>
    // <p><a href="/forgot-password">Request a new reset link</a></p>
    // </body>
    // </html>
    // """.formatted(message);
    // }

    private String createErrorPage(String message) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Password Reset Error</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            max-width: 500px;
                            margin: 50px auto;
                            padding: 20px;
                            background-color: #f8f9fa;
                        }
                        .container {
                            background: white;
                            padding: 30px;
                            border-radius: 8px;
                            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        }
                        .error-icon {
                            color: #dc3545;
                            font-size: 48px;
                            text-align: center;
                            margin-bottom: 20px;
                        }
                        .error-message {
                            color: #dc3545;
                            text-align: center;
                            margin-bottom: 20px;
                            font-size: 18px;
                        }
                        .action-link {
                            display: block;
                            text-align: center;
                            color: #007bff;
                            text-decoration: none;
                            margin-top: 20px;
                        }
                        .action-link:hover {
                            text-decoration: underline;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="error-icon">❌</div>
                        <div class="error-message">%s</div>
                        <a href="/forgot-password" class="action-link">Request a new reset link</a>
                        <a href="/login" class="action-link">Return to login</a>
                    </div>
                </body>
                </html>
                """.formatted(message);
    }

    @GetMapping("/debug-token")
    public ResponseEntity<String> debugToken(@RequestParam String token) {
        try {
            StringBuilder debugInfo = new StringBuilder();
            debugInfo.append("<h2>Token Debug Information</h2>");
            debugInfo.append("<p><strong>Original token:</strong> ").append(token).append("</p>");
            debugInfo.append("<p><strong>Token length:</strong> ").append(token.length()).append("</p>");

            // Try URL decoding
            try {
                String decoded = URLDecoder.decode(token, StandardCharsets.UTF_8.toString());
                debugInfo.append("<p><strong>URL decoded:</strong> ").append(decoded).append("</p>");
                debugInfo.append("<p><strong>Decoded length:</strong> ").append(decoded.length()).append("</p>");
            } catch (Exception e) {
                debugInfo.append("<p><strong>URL decode error:</strong> ").append(e.getMessage()).append("</p>");
            }

            // Check if token exists in database
            Optional<VerificationToken> foundToken = tokenRepository.findByToken(token);
            if (foundToken.isPresent()) {
                VerificationToken vt = foundToken.get();
                debugInfo.append("<p><strong>Token found in DB:</strong> yes</p>");
                debugInfo.append("<p><strong>Token type:</strong> ").append(vt.getTokenType()).append("</p>");
                debugInfo.append("<p><strong>Expired:</strong> ").append(vt.isExpired()).append("</p>");
                debugInfo.append("<p><strong>Used:</strong> ").append(vt.isUsed()).append("</p>");
            } else {
                debugInfo.append("<p><strong>Token found in DB:</strong> no</p>");

                // Try to find similar tokens
                List<VerificationToken> similarTokens = tokenRepository.findAll();
                debugInfo.append("<p><strong>All tokens in DB:</strong></p><ul>");
                for (VerificationToken vt : similarTokens) {
                    debugInfo.append("<li>").append(vt.getToken()).append(" (").append(vt.getTokenType())
                            .append(")</li>");
                }
                debugInfo.append("</ul>");
            }

            return ResponseEntity.ok()
                    .contentType(MediaType.TEXT_HTML)
                    .body(debugInfo.toString());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Debug error: " + e.getMessage());
        }
    }

}