package com.example.thehungryhubbackend.security.oauth2;

import com.example.thehungryhubbackend.security.oauth2.user.OAuth2UserInfo;
import com.example.thehungryhubbackend.security.oauth2.user.OAuth2UserInfoFactory;
import com.example.thehungryhubbackend.security.UserPrincipal;
import com.example.thehungryhubbackend.user.User;
import com.example.thehungryhubbackend.user.UserEntity;
import com.example.thehungryhubbackend.repository.UserRepository;
import org.apache.logging.log4j.util.InternalException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        System.out.print("\n load user from Keycloak\n");

        OAuth2UserInfo oauth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(oAuth2UserRequest.getClientRegistration().getRegistrationId(),
                oAuth2User.getAttributes());
        try {
            User user = new User();
            user.setId(oauth2UserInfo.getId());
            user.setUsername(oauth2UserInfo.getUsername());
            user.setName(oauth2UserInfo.getName());
            user.setRole("ADMIN");

            UserDetails userDetails = UserPrincipal.create(user, oAuth2User.getAttributes());

            UserEntity userEntity = new UserEntity();
            userEntity.setId(Integer.parseInt(oauth2UserInfo.getId()));
            userEntity.setUsername(oauth2UserInfo.getUsername());

            userRepository.save(userEntity);

            return UserPrincipal.create(user, oAuth2User.getAttributes());

        } catch (Exception ex) {
            throw new InternalException(ex.getMessage(), ex.getCause());
        }
    }
}
