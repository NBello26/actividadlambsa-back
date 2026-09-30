package com.example.versionamientov2.Security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer; // <-- IMPORT NECESARIO
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
// Spring Security 7 movio el soporte CORS al modulo web de Spring Framework.
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(JwtProviderProperties.class)
public class SecurityConfig {

    private final JwtProviderProperties providerProperties;

    public SecurityConfig(JwtProviderProperties providerProperties) {
        this.providerProperties = providerProperties;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:5173"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * Un decoder por emisor y un decorador que enruta cada token al decoder de su
     * proveedor, de modo que conviven Azure Entra ID y AWS Cognito en el mismo
     * resource server sin que uno pueda validar tokens del otro.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        Map<String, JwtDecoder> decodersPorEmisor = new LinkedHashMap<>();

        for (JwtProviderProperties.Provider provider : providerProperties.getProviders()) {
            NimbusJwtDecoder decoder = NimbusJwtDecoder
                    .withJwkSetUri(provider.getJwkSetUri())
                    .build();

            // createDefaultWithIssuer valida el claim "iss" exacto, la firma y las
            // fechas (exp/nbf). Un provider puede declarar varias formas de "iss".
            List<OAuth2TokenValidator<Jwt>> validadores = new ArrayList<>();
            for (String issuer : provider.getIssuers()) {
                validadores.add(JwtValidators.createDefaultWithIssuer(issuer));
            }
            // Si no se declara audiencia, no se valida "aud" (comportamiento previo).
            if (!provider.getAudiences().isEmpty()) {
                validadores.add(audienceValidator(provider.getAudiences()));
            }
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validadores));

            for (String issuer : provider.getIssuers()) {
                decodersPorEmisor.put(issuer, decoder);
            }
        }

        return new MultiIssuerJwtDecoder(decodersPorEmisor);
    }

    /**
     * Un token solo sirve para este backend si identifica a este backend como su
     * destinatario. Evita que un token legitimo emitido para otra API se pueda
     * reutilizar aqui.
     *
     * <p>El claim no siempre se llama igual: Azure Entra ID y el ID token de
     * Cognito lo ponen en "aud", pero el ACCESS token de Cognito lo pone en
     * "client_id" (por diseno, para que un access token no se pueda usar donde se
     * espera un ID token). Por eso se aceptan los dos.</p>
     */
    private OAuth2TokenValidator<Jwt> audienceValidator(List<String> audiences) {
        return token -> {
            List<String> aud = token.getClaimAsStringList("aud");
            List<String> clientId = token.getClaimAsStringList("client_id");

            boolean aceptada = contieneUno(aud, audiences) || contieneUno(clientId, audiences);

            if (aceptada) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token",
                    "El token no fue emitido para este backend. aud: " + aud + ", client_id: " + clientId,
                    null));
        };
    }

    private boolean contieneUno(List<String> valores, List<String> esperados) {
        return valores != null && valores.stream().anyMatch(esperados::contains);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(Customizer.withDefaults())
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/v1/public").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthenticationConverter()) // Registramos el conversor de roles
                )
            );
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(this::autoridades);
        return jwtAuthenticationConverter;
    }

    /**
     * Arma los roles (autoridades) del token a partir de donde el proveedor los
     * publica:
     *
     * <ul>
     *   <li>Azure Entra ID los trae en el claim "roles".</li>
     *   <li>AWS Cognito no usa "roles": sus permisos son los grupos del claim
     *       "cognito:groups", y ese claim solo existe en el ID token, no en el
     *       access token que es el que se envia a un resource server. Por eso un
     *       access token de Cognito llega sin ningun rol.</li>
     * </ul>
     *
     * <p>Cuando el token no trae ninguno, se aplica el "default-role" declarado para
     * el proveedor que lo emitio. Asi el rol por defecto solo es un respaldo: si el
     * usuario pertenece a un grupo, el grupo manda.</p>
     *
     * <p>El prefijo es "ROLE_" y no el "SCOPE_" que pone Spring Security por
     * defecto, para poder usar hasRole(...) en vez de hasAuthority(...).</p>
     */
    private Collection<GrantedAuthority> autoridades(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new LinkedHashSet<>();

        authorities.addAll(rolesDelClaim(jwt, "roles"));           // Azure Entra ID
        authorities.addAll(rolesDelClaim(jwt, "cognito:groups"));  // AWS Cognito

        if (authorities.isEmpty()) {
            authorities.addAll(rolPorDefecto(jwt));
        }

        return authorities;
    }

    private Collection<GrantedAuthority> rolesDelClaim(Jwt jwt, String claim) {
        List<String> roles = jwt.getClaimAsStringList(claim);
        if (roles == null) {
            return List.of();
        }
        return roles.stream()
                .filter(rol -> rol != null && !rol.isBlank())
                .map(rol -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + rol.trim()))
                .toList();
    }

    private Collection<GrantedAuthority> rolPorDefecto(Jwt jwt) {
        String issuer = jwt.getClaimAsString("iss");
        if (issuer == null) {
            return List.of();
        }

        for (JwtProviderProperties.Provider provider : providerProperties.getProviders()) {
            String rol = provider.getDefaultRole();
            if (rol == null || rol.isBlank()) {
                continue;
            }
            if (provider.getIssuers().contains(issuer)) {
                return List.of(new SimpleGrantedAuthority("ROLE_" + rol.trim()));
            }
        }

        return List.of();
    }
}
