package com.zev.identity_guard.controller;

import com.zev.identity_guard.dto.AuthRequest;
import com.zev.identity_guard.dto.AuthResponse;
import com.zev.identity_guard.dto.AuthResult;
import com.zev.identity_guard.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;


    @Value("${spring.application.security.jwt.refresh-token-expiration}")
    private long refreshExpiration;


    @PostMapping("/register")
    public ResponseEntity<Map<String,String>> register(@Valid @RequestBody AuthRequest authRequest){
        authService.register(authRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("message","User registered successfully"));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest authRequest){

        AuthResult result=authService.login(authRequest);

        ResponseCookie refreshCookie= buildRefreshCookie(result.refreshToken(),Duration.ofMillis(refreshExpiration));

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,refreshCookie.toString())
                .body(new AuthResponse(result.accessToken()));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(
            @CookieValue(name = "refresh_token",required = false) String refreshTokenStr
    ){
        if(refreshTokenStr==null || refreshTokenStr.isBlank()){
            throw new IllegalArgumentException("Refresh Token is missing");
        }

        AuthResult result = authService.refreshToken(refreshTokenStr);

        ResponseCookie newRefreshCookie= buildRefreshCookie(result.refreshToken(),Duration.ofMillis(refreshExpiration));

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,newRefreshCookie.toString())
                .body(new AuthResponse(result.accessToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String,String>> logout(
            @CookieValue(name = "refresh_token",required = false) String refreshToken
    ){
        if(refreshToken!=null && !refreshToken.isBlank()){
            authService.logout(refreshToken);
        }

        ResponseCookie deleteCookie= buildRefreshCookie("",Duration.ZERO);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,deleteCookie.toString())
                .body(Map.of("message","Logged out Successfully"));
    }

    private ResponseCookie buildRefreshCookie(String token, Duration maxAge){

        return ResponseCookie.from("refresh_token",token)
                .httpOnly(true)
                .secure(false)
                .path("/api/auth")
                .maxAge(maxAge)
                .sameSite("Strict")
                .build();
    }
}
