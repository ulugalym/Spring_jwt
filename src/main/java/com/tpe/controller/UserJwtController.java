package com.tpe.controller;

import com.tpe.dto.LoginRequest;
import com.tpe.dto.RegisterRequest;
import com.tpe.security.service.JwtUtils;
import com.tpe.service.UserService;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class UserJwtController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    // !!! ***************** REGISTER ****************************
    @PostMapping("/register") // http://localhost:8080/register  + POST
    public ResponseEntity<String> registerUser(@RequestBody @Valid RegisterRequest request){

        userService.registerUser(request);

        String responseMessage = "User registered successfully";

        return new ResponseEntity<>(responseMessage, HttpStatus.CREATED);

    }

    // !!! ****************** LOGIN ********************************
    @PostMapping("/login") // http://localhost:8080/login  + POST
    public ResponseEntity<Map<String, String>> login(@RequestBody @Valid LoginRequest request){
        // !!! kullanica authenticate edilecek
        Authentication authentication =authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUserName(), request.getPassword()));
        // !!! JWT token uretiliyor
        String token = jwtUtils.generateToken(authentication);

        Map<String, String> map = new HashMap<>();
        map.put("token", token);
        return new ResponseEntity<>(map, HttpStatus.CREATED);


    }
}