package com.zev.identity_guard.dto;

public record AuthResult(
        String accessToken,
        String refreshToken
) {}