package com.example.notepad.filter;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.notepad.TokenUtil;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Component
public class jwtFilter extends OncePerRequestFilter {

    @Autowired
    private TokenUtil tokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        // ✅ Step 1: Check Bearer token
        if (header != null && header.startsWith("Bearer ")) {

            String token = header.substring(7);

            Claims claims = tokenUtil.validateToken(token);

            // ✅ Step 2: If token valid
            if (claims != null) {

                String username = claims.getSubject();
                String role = (String) claims.get("role");

                // ✅ Step 3: Create authorities
                List<GrantedAuthority> authorities =
                        List.of(new SimpleGrantedAuthority("ROLE_" + role));

                // ✅ Step 4: Create authentication object
                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(
                                username,
                                null,
                                authorities
                        );

                // ✅ Step 5: Set authentication
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }

        // ✅ Step 6: Continue filter chain
        filterChain.doFilter(request, response);
    }
}