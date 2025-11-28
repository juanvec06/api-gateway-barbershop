package com.example.apigateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.CrossOrigin;

import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
//@CrossOrigin(origins = "http://localhost:4200")
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
            .authorizeExchange(exchanges -> exchanges
                
                // ------------------------------------------------------------
                // 1. RUTAS PÚBLICAS (No requieren login)
                // ------------------------------------------------------------
                // Servicios: Listar, detalle, barberos por servicio
                .pathMatchers(HttpMethod.GET, "/servicios/public/**").permitAll()
                // Barberos: Perfil, servicios por barbero
                .pathMatchers(HttpMethod.GET, "/barberos/public/**").permitAll()

                // ------------------------------------------------------------
                // 2. ROL: ADMINISTRADOR
                // ------------------------------------------------------------
                // Servicios (Admin)
                .pathMatchers("/servicios/admin/**").hasAnyAuthority("admin", "administrador")
                
                // Barberos (Admin)
                .pathMatchers("/barberos/admin/**").hasAnyAuthority("admin", "administrador")
                
                // Reportes (Admin)
                .pathMatchers("/reportes/admin/**").hasAnyAuthority("admin", "administrador")

                // ------------------------------------------------------------
                // 3. ROL: CLIENTE
                // ------------------------------------------------------------
                // Reservas: Crear
                .pathMatchers(HttpMethod.POST, "/reservas").hasAuthority("cliente")
                // Reservas: Ver historial propio
                .pathMatchers(HttpMethod.GET, "/reservas/cliente/**").hasAuthority("cliente")
                // Reservas: Reprogramar y Cancelar (usamos * para el ID)
                .pathMatchers(HttpMethod.PUT, "/reservas/*/reprogramar").hasAuthority("cliente")
                .pathMatchers(HttpMethod.PUT, "/reservas/*/cancelar").hasAuthority("cliente")

                // ------------------------------------------------------------
                // 4. ROL: BARBERO
                // ------------------------------------------------------------
                // Reservas: Ver agenda asignada
                .pathMatchers(HttpMethod.GET, "/reservas/barbero/**").hasAuthority("barbero")
                // Reservas: Cambiar estado (INICIADA/FINALIZADA)
                .pathMatchers(HttpMethod.PUT, "/reservas/*/estado").hasAuthority("barbero")
                // Reportes: Métricas propias
                .pathMatchers(HttpMethod.GET, "/reportes/barbero/**").hasAuthority("barbero")

                // ------------------------------------------------------------
                // RESTO DE RUTAS
                // ------------------------------------------------------------
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwtSpec -> jwtSpec.jwtAuthenticationConverter(grantedAuthoritiesExtractor()))
            )
            .csrf(ServerHttpSecurity.CsrfSpec::disable); // Deshabilitar CSRF para APIs REST

        return http.build();
    }

    // Método para convertir el JWT en roles de Spring Security
    Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverterWebFlux());
        return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
    }
}

// Convertidor de roles de Keycloak
class KeycloakRealmRoleConverterWebFlux implements Converter<Jwt, Collection<GrantedAuthority>> {
    // Asegúrate de que este ID coincida con tu cliente en Keycloak si usas roles de cliente
    private static final String KEYCLOAK_CLIENT_ID_WITH_USER_ROLES = "sistema-desktop"; 
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KeycloakRealmRoleConverterWebFlux.class);

    @Override
    @SuppressWarnings("unchecked")
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Map<String, Object> claims = jwt.getClaims();
        if (claims == null) {
            return Collections.emptyList();
        }

        // 1. Buscar roles en resource_access (Roles de Cliente)
        Map<String, Object> resourceAccess = (Map<String, Object>) claims.get("resource_access");
        if (resourceAccess != null && resourceAccess.containsKey(KEYCLOAK_CLIENT_ID_WITH_USER_ROLES)) {
            Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(KEYCLOAK_CLIENT_ID_WITH_USER_ROLES);
            if (clientAccess != null && clientAccess.containsKey("roles")) {
                List<String> clientRoles = (List<String>) clientAccess.getOrDefault("roles", Collections.emptyList());
                if (!clientRoles.isEmpty()) {
                    return clientRoles.stream()
                            .map(SimpleGrantedAuthority::new) // Mapea tal cual viene (ej: "barbero")
                            .collect(Collectors.toList());
                }
            }
        }

        // 2. Buscar roles en realm_access (Roles de Reino)
        Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            List<String> realmRoles = (List<String>) realmAccess.getOrDefault("roles", Collections.emptyList());
            if (!realmRoles.isEmpty()) {
                return realmRoles.stream()
                        .map(SimpleGrantedAuthority::new) // Mapea tal cual viene (ej: "admin")
                        .collect(Collectors.toList());
            }
        }
        
        return Collections.emptyList();
    }
}