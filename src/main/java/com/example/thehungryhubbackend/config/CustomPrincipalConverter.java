package com.example.thehungryhubbackend.config;

import com.example.thehungryhubbackend.security.oauth2.CustomOAuth2UserService;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.stereotype.Component;

@Component
public class CustomPrincipalConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final OAuth2ClientProperties oAuth2ClientProperties;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthorizedClientService clientService;

    public CustomPrincipalConverter(OAuth2ClientProperties oAuth2ClientProperties,
                                    CustomOAuth2UserService customOAuth2UserService,
                                    OAuth2AuthorizedClientService clientService) {
        this.oAuth2ClientProperties = oAuth2ClientProperties;
        this.customOAuth2UserService = customOAuth2UserService;
        this.clientService = clientService;
    }


    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                jwt.getTokenValue(),
                jwt.getIssuedAt(),
                jwt.getExpiresAt()
        );

        return oAuth2ClientProperties.getProvider().entrySet().stream()
                .filter(provideEntry -> provideEntry.getValue().getIssuerUri().equals(jwt.getClaim("iss")))
                .findFirst().map(providerEntry -> {
                    OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(providerEntry.getKey(),
                            (String) jwt.getClaims().get(providerEntry.getValue().getUserNameAttribute())
                    );
                    OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(client.getClientRegistration(), accessToken);

                    OAuth2User oAuth2User = customOAuth2UserService.loadUser(oAuth2UserRequest);
                    return new BearerTokenAuthentication(oAuth2User, accessToken, oAuth2User.getAuthorities());
                })
                .orElseThrow( () -> new RuntimeException("Error finding registered authorized client"));
    }
}
