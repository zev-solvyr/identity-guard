package com.zev.identity_guard.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/me")
    public ResponseEntity<Map<String,Object>> getCurrentUser(Authentication authentication){
        return ResponseEntity.ok(Map.of(
                "userId", authentication.getName(),
                "authorities",authentication.getAuthorities(),
                "message","You accessed a protected route using a valid stateless JWt!"
        ));
    }
}
