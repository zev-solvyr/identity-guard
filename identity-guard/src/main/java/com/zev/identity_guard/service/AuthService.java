package com.zev.identity_guard.service;

import com.zev.identity_guard.dto.AuthRequest;
import com.zev.identity_guard.dto.AuthResult;
import com.zev.identity_guard.entity.AppUser;
import com.zev.identity_guard.entity.RefreshToken;
import com.zev.identity_guard.repository.RefreshTokenRepository;
import com.zev.identity_guard.repository.UserRepository;
import com.zev.identity_guard.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Value("${spring.application.security.jwt.refresh-token-expiration}")
    private long refreshExpiration;

    // 1.  Register

    @Transactional
    public void register(AuthRequest request){

        if(userRepository.existsByEmail(request.email())){
            throw new IllegalArgumentException("Email already exists");
        }

        AppUser newUser= AppUser.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role("ROLE_USER")
                .build();

        userRepository.save(newUser);
    }

    //2. Login

    @Transactional
    public AuthResult login(AuthRequest request){

        //find user in db

        AppUser user= userRepository.findByEmail(request.email())
                .orElseThrow(()->new IllegalArgumentException("Invalid email or password"));

        //check password matches or not
        if(!passwordEncoder.matches(request.password(),user.getPassword())){
            throw  new IllegalArgumentException("Invalid email or password");
        }

        //generate accesstoken
        String accessToken= jwtService.generateAccessToken(user);

        //generate refresh token

        String refreshToken= jwtService.generateRefreshToken();

        RefreshToken refreshTokenEntity= RefreshToken.builder()
                .user(user)
                .token(refreshToken)
                .expiryDate(Instant.now().plusMillis(refreshExpiration))
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshTokenEntity);

        return  new AuthResult(accessToken,refreshToken);

    }

    // 3. Refresh token rotation

    @Transactional
    public AuthResult refreshToken(String oldRefreshToken){

        // find token is present or not
        RefreshToken existingToken= refreshTokenRepository.findByToken(oldRefreshToken)
                .orElseThrow(()-> new IllegalArgumentException("Invalid refresh token"));

        //check if it was revoked manually ( logout or already rotated)

        if(existingToken.isRevoked()){
            throw new IllegalArgumentException("Token is already revoked");
        }
        // check token window 7 days is expired
        if(existingToken.getExpiryDate().isBefore(Instant.now())){
            existingToken.setRevoked(true);
            refreshTokenRepository.save(existingToken);
            throw new IllegalArgumentException("Token is expired");
        }

        //revoke the old token so it cannot be used twice

        existingToken.setRevoked(true);
        refreshTokenRepository.save(existingToken);

        //generate new pair (access + refresh)

        AppUser user=existingToken.getUser();

        String newAccessToken= jwtService.generateAccessToken(user);
        String newRefreshToken= jwtService.generateRefreshToken();

        RefreshToken newRefreshTokenEntity= RefreshToken.builder()
                .user(user)
                .token(newRefreshToken)
                .expiryDate(Instant.now().plusMillis(refreshExpiration))
                .revoked(false)
                .build();

        refreshTokenRepository.save(newRefreshTokenEntity);
        return new AuthResult(newAccessToken,newRefreshToken);
    }


    //4. Logout(revoke the token)

    @Transactional
    public void logout(String refreshToken){
        refreshTokenRepository.findByToken(refreshToken)
                .ifPresent(token->
                {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                });
    }


}
