package com.sideproject.diary.service;


import com.sideproject.diary.dto.*;
import com.sideproject.diary.entity.RefreshToken;
import com.sideproject.diary.entity.User;
import com.sideproject.diary.repository.UserRepository;
import com.sideproject.diary.token.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    @Value("${app.jwt.accessTokenExpiration}")
    private int accessTokenExpirationInMs;

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;

    public ApiResponse<JwtAuthenticationResponse> authenticateUser(LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsernameOrEmail(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String accessToken = tokenProvider.generateToken(authentication);

            // 사용자 정보로 refresh token 생성
            User user = userRepository.findByUsername(authentication.getName())
                    .or(() -> userRepository.findByEmail(authentication.getName()))
                    .orElseThrow(() -> new RuntimeException("User not found"));

            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

            JwtAuthenticationResponse tokenResponse = new JwtAuthenticationResponse(
                    accessToken,
                    refreshToken.getToken(),
                    (long) accessTokenExpirationInMs / 1000
            );

            return ApiResponse.success(tokenResponse, "Login successful");

        } catch (Exception e) {
            log.error("Authentication failed for user: {}", loginRequest.getUsernameOrEmail(), e);
            return ApiResponse.unauthorized("Invalid username or password");
        }
    }

    public ApiResponse<JwtAuthenticationResponse> refreshToken(TokenRefreshRequest request) {
        String refreshToken = request.getRefreshToken();
        return refreshTokenService.findByToken(refreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    // 새로운 access token 생성
                    Authentication auth = new UsernamePasswordAuthenticationToken(user.getUsername(), null, null);
                    String newAccessToken = tokenProvider.generateToken(auth);
                    JwtAuthenticationResponse tokenResponse = new JwtAuthenticationResponse(newAccessToken, refreshToken, (long) accessTokenExpirationInMs / 1000);
                    return ApiResponse.success(tokenResponse, "Refresh token successful");
                }).orElse(ApiResponse.unauthorized("Refresh token is not in database!"));
    }

    public ApiResponse<Void> logout(String refreshToken) {
        refreshTokenService.findByToken(refreshToken)
                .ifPresent(token -> refreshTokenService.deleteByUser(token.getUser()));

        return ApiResponse.success("Logout successful");
    }
    public ApiResponse<Void> registerUser(SignUpRequest signUpRequest) {
        try {
            // 사용자명 중복 확인
            if (userRepository.existsByUsername(signUpRequest.getUsername())) {
                return ApiResponse.badRequest("Username is already taken!");
            }

            // 이메일 중복 확인
            if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                return ApiResponse.badRequest("Email Address already in use!");
            }

            // 새 사용자 생성
            User user = User.builder()
                    .username(signUpRequest.getUsername())
                    .email(signUpRequest.getEmail())
                    .password(passwordEncoder.encode(signUpRequest.getPassword()))
                    .build();

            userRepository.save(user);

            return ApiResponse.success("User registered successfully");

        } catch (Exception e) {
            log.error("User registration failed", e);
            return ApiResponse.internalServerError("Registration failed. Please try again.");
        }
    }
}
