package com.sideproject.diary.controller;


import com.sideproject.diary.dto.ApiResponse;
import com.sideproject.diary.dto.JwtAuthenticationResponse;
import com.sideproject.diary.dto.LoginRequest;
import com.sideproject.diary.dto.SignUpRequest;
import com.sideproject.diary.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signin")
    public ResponseEntity<ApiResponse<JwtAuthenticationResponse>> authenticateUser(
            @Valid @RequestBody LoginRequest loginRequest) {

        ApiResponse<JwtAuthenticationResponse> response = authService.authenticateUser(loginRequest);

        return ResponseEntity
                .status(response.getStatusCode())
                .body(response);
    }

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<Void>> registerUser(
            @Valid @RequestBody SignUpRequest signUpRequest) {

        ApiResponse<Void> response = authService.registerUser(signUpRequest);

        return ResponseEntity
                .status(response.getStatusCode())
                .body(response);
    }


}
