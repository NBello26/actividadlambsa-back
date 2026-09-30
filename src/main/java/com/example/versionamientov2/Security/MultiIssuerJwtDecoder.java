package com.example.versionamientov2.Security;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import com.nimbusds.jwt.SignedJWT;

/**
 * JwtDecoder que acepta tokens de varios proveedores de identidad a la vez
 * (Azure Entra ID y AWS Cognito).
 *
 * <p>Spring Security solo valida un "issuer-uri" por instancia, asi que aqui se
 * inspecciona el claim "iss" del token (SIN verificar la firma) unicamente para
 * elegir a que decoder se delega. Cada decoder delegado si valida firma,Audience,
 * fechas y su propio "iss", de modo que elegir el decoder por el "iss" no abre
 * la puerta a tokens de otro tenant: si el "iss" no esta en la lista, se rechaza.</p>
 */
public class MultiIssuerJwtDecoder implements JwtDecoder {

    private final Map<String, JwtDecoder> decodersPorEmisor;

    public MultiIssuerJwtDecoder(Map<String, JwtDecoder> decodersPorEmisor) {
        this.decodersPorEmisor = new LinkedHashMap<>(decodersPorEmisor);
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        String emisor = leerEmisor(token);

        JwtDecoder decoder = decodersPorEmisor.get(emisor);
        if (decoder == null) {
            throw new JwtException("El token no fue emitido por un proveedor registrado. iss recibido: " + emisor);
        }

        return decoder.decode(token);
    }

    private String leerEmisor(String token) {
        try {
            // Se lee el claim crudo porque segun la version de Nimbus "iss" se
            // expone como String o como lista de String.
            Object iss = SignedJWT.parse(token).getJWTClaimsSet().getClaim("iss");

            if (iss instanceof String emisor) {
                return emisor;
            }
            if (iss instanceof List<?> emisores && !emisores.isEmpty()) {
                return String.valueOf(emisores.get(0));
            }
            throw new JwtException("El token no contiene el claim iss");
        } catch (ParseException e) {
            throw new JwtException("El token no es un JWT valido", e);
        }
    }
}
