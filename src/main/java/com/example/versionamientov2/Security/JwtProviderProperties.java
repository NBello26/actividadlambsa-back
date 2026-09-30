package com.example.versionamientov2.Security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Lista de proveedores de identidad (OpenID Connect) que el backend acepta como
 * emisores de tokens. Cada proveedor tiene su propio conjunto de llaves publicas
 * (JWK Set) y sus valores de "iss" y "aud" admitidos.
 *
 * <p>Se configura en application.yaml bajo app.security.jwt.providers</p>
 */
@ConfigurationProperties(prefix = "app.security.jwt")
public class JwtProviderProperties {

    private List<Provider> providers = new ArrayList<>();

    public List<Provider> getProviders() {
        return providers;
    }

    public void setProviders(List<Provider> providers) {
        this.providers = providers;
    }

    public static class Provider {

        // Solo identifica al proveedor en los logs de arranque.
        private String name;

        // URL donde el proveedor publica sus llaves publicas (JWK Set).
        private String jwkSetUri;

        // Valores admitidos del claim "iss". Si el token trae otro, se rechaza.
        private List<String> issuers = new ArrayList<>();

        // Valores admitidos del claim "aud". Vacio = no se valida la audiencia.
        private List<String> audiences = new ArrayList<>();

        // Rol que se asigna cuando el token no trae ninguno. Util para Cognito,
        // cuyo access token nunca trae roles. Vacio = no se asigna nada.
        private String defaultRole;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getJwkSetUri() {
            return jwkSetUri;
        }

        public void setJwkSetUri(String jwkSetUri) {
            this.jwkSetUri = jwkSetUri;
        }

        public List<String> getIssuers() {
            return issuers;
        }

        public void setIssuers(List<String> issuers) {
            this.issuers = issuers;
        }

        public List<String> getAudiences() {
            return audiences;
        }

        public void setAudiences(List<String> audiences) {
            this.audiences = audiences;
        }

        public String getDefaultRole() {
            return defaultRole;
        }

        public void setDefaultRole(String defaultRole) {
            this.defaultRole = defaultRole;
        }
    }
}
