package org.codewithanish.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@ConfigurationProperties(prefix = "oauth")
@Configuration
@Getter
@Setter
public class OAuthProperties {
    private List<Jwt> jwts;
    @Getter
    @Setter
    public static class Jwt{
        private String issuerUrl;
        private String jwksUrl;
    }
}
