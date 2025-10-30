package com.example.thehungryhubbackend.security.oauth2;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class CustomOidcUserService extends OidcUserService {
    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) {
        System.out.println("oidc");
        // 🔁 Call default implementation to get the OIDC user
        OidcUser oidcUser = super.loadUser(userRequest);


        // ✅ Extract id_token claims
        OidcIdToken idToken = userRequest.getIdToken();
        Map<String, Object> idTokenClaims = idToken.getClaims();
        System.out.println("🧾 ID Token Claims: " + idTokenClaims);

        // ✅ Extract userinfo (merged by default if provider supports it)
        Map<String, Object> attributes = oidcUser.getAttributes();
        System.out.println("👤 User Info Attributes: " + attributes);

        // Example: add a role or enrich user info
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));


        return new DefaultOidcUser(authorities, idToken, "sub"); // "email" is the claim used as username
    }
}
