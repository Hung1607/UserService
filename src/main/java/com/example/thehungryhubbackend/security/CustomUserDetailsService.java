package com.example.thehungryhubbackend.security;

import com.example.thehungryhubbackend.repository.UserRepository;
import com.example.thehungryhubbackend.user.UserEntity;
//import com.example.thehungryhubbackend.repository.UserRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findUserByUsername(username);

        ArrayList<String> roles = new ArrayList<>();
        roles.add(userEntity.getRole());

        UserDetails userDetails = new User(userEntity.getUsername(), userEntity.getPassword(), mapRoles(roles));
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken
                (userDetails, null,
                        userDetails.getAuthorities());

        return userDetails;
    }

    private Collection<GrantedAuthority> mapRoles(List<String> roles) {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role))  // Prefix "ROLE_" for Spring Security convention
                .collect(Collectors.toList());
    }
}
