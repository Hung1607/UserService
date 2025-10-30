package com.example.thehungryhubbackend.controller;

import com.example.thehungryhubbackend.security.CurrentUser;
import com.example.thehungryhubbackend.security.UserPrincipal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/user")
public class AdminController {
    @GetMapping("/getAll")
    @Secured("ROLE_ADMIN")
    public ResponseEntity<String> getData() {
        try {
            System.out.println("data received");
            return ResponseEntity.ok("data received");
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/me")
    @Secured("ROLE_ADMIN")
    public ResponseEntity<String> getCurrentUser(@CurrentUser UserPrincipal userPrincipal) {
        System.out.println("user_fetched");
        return ResponseEntity.ok("ok");
    }

}
