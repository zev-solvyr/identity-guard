package com.zev.identity_guard.security;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;


    @Override
    protected void doFilterInternal(
           @NonNull HttpServletRequest request,
           @NonNull HttpServletResponse response,
           @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        //1. check if Authorization header exists and starts with Bearer

        final String authHeader= request.getHeader("Authorization");

        if(authHeader==null|| !authHeader.startsWith("Bearer")){
            filterChain.doFilter(request,response);
            return;
        }
        //2. extract raw jwt token

        final String jwt= authHeader.substring(7);

        try{
            //3. verify signature and expiration and extract userid, role
            String userId= jwtService.extractUserId(jwt);
            String role=jwtService.extractRole(jwt);

            //4. user is valid and not authenticated early
            if(userId!=null && SecurityContextHolder.getContext().getAuthentication()==null){
                List<SimpleGrantedAuthority> authorities=List.of(new SimpleGrantedAuthority(role));

                UsernamePasswordAuthenticationToken authToken= new UsernamePasswordAuthenticationToken(
                        userId,
                        null,
                        authorities
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                //5. stamp the user into SecurityContextHolder

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        catch (JwtException | IllegalArgumentException e){
                SecurityContextHolder.clearContext();
        }
        //6. continue down the filter chain

        filterChain.doFilter(request,response);
    }
}
