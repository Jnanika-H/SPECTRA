package com.spectra.controller;

import com.spectra.dto.LoginRequest;
import com.spectra.dto.LoginResponse;
import com.spectra.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtTokenProvider jwtProvider;

    /**
     * POST /api/login
     * Body: { "username": "admin", "password": "password" }
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest req) {
        Authentication auth = authManager.authenticate(
            new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword())
        );
        String token = jwtProvider.generateToken(auth);
        log.info("Login: {}", req.getUsername());
        return ResponseEntity.ok(new LoginResponse(token, req.getUsername(), "Login successful"));
    }
}


