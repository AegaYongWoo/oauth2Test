package org.oauth.oauth2.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Map;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class OAuth2UserService extends DefaultOAuth2UserService {
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        log.info("oAuth2User: {}", oauth2User);
        final Map<String, Object> attributes = oauth2User.getAttributes();
        final String oauthId = String.valueOf(attributes.get("id"));
        final String oauthType = userRequest.getClientRegistration().getRegistrationId();
        final String nickname = String.valueOf(((Map<String, Object>)attributes.get("properties")).get("nickname"));

        log.info(oauthId);
        log.info(oauthType);
        log.info(nickname);

        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_GUEST"));

        /* maybe
        if (userRepository.findByOAuthIdAndOAuthType(oauthId, oauthType) != null) {
            // 로그인 ROLE_USER
            authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
            return new DefaultOAuth2User(authorities, oauth2User.getAttributes(), "id");
        }
         */

        // ROLE_GUEST
        return new DefaultOAuth2User(authorities, oauth2User.getAttributes(), "id");
    }
}