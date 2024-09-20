package org.codewithanish.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private OAuthProperties oAuthProperties;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(r -> r
                //.requestMatchers("/demo-service/employee").hasAuthority("ROLE_USER")
                .anyRequest().authenticated());
        httpSecurity.oauth2ResourceServer(o -> o.authenticationManagerResolver(authenticationManagerResolver()));
        httpSecurity.sessionManagement( s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        httpSecurity.cors(c -> c.configurationSource(corsConfigurationSource()));
        return httpSecurity.build();
    }

   private JwtIssuerAuthenticationManagerResolver authenticationManagerResolver()
   {
      return new JwtIssuerAuthenticationManagerResolver(oAuthProperties.getJwts().stream().collect(Collectors.toMap(OAuthProperties.Jwt::getIssuerUrl,
              j -> authenticationManager(j.getJwksUrl())))::get);
   }

   private AuthenticationManager authenticationManager(String jwksUrl)
   {
       NimbusJwtDecoder  decoder = NimbusJwtDecoder.withJwkSetUri(jwksUrl).build();
       // to validate the token was created for client "api-client-id" from the authorization application
       decoder.setJwtValidator(new JwtClaimValidator<List<String>>
              (JwtClaimNames.AUD, list -> list != null && list.contains("api-client-id")));
       JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
       provider.setJwtAuthenticationConverter(jwtAuthenticationConverter());
       return new ProviderManager(provider);
   }

   private JwtAuthenticationConverter jwtAuthenticationConverter()
   {
       JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
       converter.setJwtGrantedAuthoritiesConverter(
               jwt -> {
                   if(jwt.hasClaim("authorities"))
                   {
                      return  jwt.getClaimAsStringList("authorities").stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
                   }else {
                       throw new AccessDeniedException("authorities not found in the token");
                   }
               }
       );
       return converter;
   }

   private CorsConfigurationSource corsConfigurationSource()
   {
       CorsConfiguration corsConfiguration = new CorsConfiguration().applyPermitDefaultValues();
       corsConfiguration.addAllowedMethod("*");
       corsConfiguration.setExposedHeaders(List.of("Access-Control-Allow-Origin"));
       UrlBasedCorsConfigurationSource corsConfigurationSource = new UrlBasedCorsConfigurationSource();
       corsConfigurationSource.registerCorsConfiguration("/**",corsConfiguration);
       return  corsConfigurationSource;
   }

}
