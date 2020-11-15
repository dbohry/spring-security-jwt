package com.danielbohry.springsecurityjwt.apis;

import com.danielbohry.springsecurityjwt.models.AuthenticationRequest;
import com.danielbohry.springsecurityjwt.models.AuthenticationResponse;
import com.danielbohry.springsecurityjwt.utils.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
public class HelloController {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService myUserDetailsService;
    private final JwtUtil jwt;

    public HelloController(AuthenticationManager authenticationManager,
                           UserDetailsService myUserDetailsService,
                           JwtUtil jwt) {
        this.authenticationManager = authenticationManager;
        this.myUserDetailsService = myUserDetailsService;
        this.jwt = jwt;
    }

    @PostMapping("authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        final UserDetails userDetails = myUserDetailsService.loadUserByUsername(request.getUsername());
        String token = jwt.generateToken(userDetails);

        return ResponseEntity.ok(new AuthenticationResponse(token));
    }

    @GetMapping("hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello there");
    }

}
