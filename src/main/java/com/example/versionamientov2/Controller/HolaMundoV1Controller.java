package com.example.versionamientov2.Controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api/v1")
public class HolaMundoV1Controller {
    @GetMapping("/admin")
    @PreAuthorize("hasRole('Administrador')")
    public String saludo(@AuthenticationPrincipal Jwt jwt) {
        var usuario= jwt.getClaims();
        return "hola admin "+ usuario;
    }
    @GetMapping("/usuario")
    @PreAuthorize("hasRole('Usuario')")
    public String despedida() {
        return "adios roles usuarios";
    }
    @GetMapping("/ambos-roles")
    @PreAuthorize("hasAnyRole('Administrador', 'Usuario')")
    public String holaAmbosRoles() {
        return "aceptando roles admin - user ";
    }
    @GetMapping("/todos-roles")
    public String holaRoles() {
        return "aceptando todos los roles";
    }
    @GetMapping("/public")
    public String publicos() {
        return "Este es un endpoint publico";
    }
    
    
}
