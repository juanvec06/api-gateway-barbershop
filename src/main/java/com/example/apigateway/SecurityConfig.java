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
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfiguration;

import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(ServerHttpSecurity.CsrfSpec::disable) // Deshabilitar CSRF para APIs REST
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers(HttpMethod.OPTIONS).permitAll()

                // ------------------------------------------------------------
                // 1. RUTAS PÚBLICAS (No requieren login)
                // ------------------------------------------------------------
                .pathMatchers(HttpMethod.GET, "/servicios/public/**").permitAll()
                .pathMatchers(HttpMethod.GET, "/barberos/public/**").permitAll()

                // ------------------------------------------------------------
                // 2. ROL: ADMINISTRADOR
                // ------------------------------------------------------------
                .pathMatchers("/servicios/admin/**").hasRole("ADMIN")
                .pathMatchers("/barberos/admin/**").hasRole("ADMIN")
                .pathMatchers("/reportes/admin/**").hasRole("ADMIN")

                // ------------------------------------------------------------
                // 3. ROL: CLIENTE
                // ------------------------------------------------------------
                .pathMatchers(HttpMethod.POST, "/reservas").hasRole("CLIENT")
                .pathMatchers(HttpMethod.GET, "/reservas/cliente/**").hasRole("CLIENT")
                .pathMatchers(HttpMethod.PUT, "/reservas/*/reprogramar").hasRole("CLIENT")
                .pathMatchers(HttpMethod.PUT, "/reservas/*/cancelar").hasRole("CLIENT")

                // ------------------------------------------------------------
                // 4. ROL: BARBERO
                // ------------------------------------------------------------
                .pathMatchers(HttpMethod.GET, "/reservas/barbero/**").hasRole("BARBER")
                .pathMatchers(HttpMethod.PUT, "/reservas/*/estado").hasRole("BARBER")
                .pathMatchers(HttpMethod.GET, "/reportes/barbero/**").hasRole("BARBER")

                // ------------------------------------------------------------
                // RESTO DE RUTAS
                // ------------------------------------------------------------
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwtSpec -> jwtSpec.jwtAuthenticationConverter(grantedAuthoritiesExtractor()))
            );

        return http.build();
    }

    // Método para convertir el JWT en roles de Spring Security (reactivo)
    Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverterWebFlux());
        return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
    }

    /**
     * Configuración CORS centralizada.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:4200"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept", "X-Requested-With"));
        config.setExposedHeaders(List.of("Authorization"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}


// Convertidor de roles de Keycloak
class KeycloakRealmRoleConverterWebFlux implements Converter<Jwt, Collection<GrantedAuthority>> {
    // Ajusta si usas roles de cliente con otro client-id
    private static final String KEYCLOAK_CLIENT_ID_WITH_USER_ROLES = "frontend-client";
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KeycloakRealmRoleConverterWebFlux.class);

    @Override
    @SuppressWarnings("unchecked")
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Map<String, Object> claims = jwt.getClaims();
        if (claims == null) {
            return Collections.emptyList();
        }

        // 1. Buscar roles en resource_access (Roles de Cliente)
        try {
            Map<String, Object> resourceAccess = (Map<String, Object>) claims.get("resource_access");
            if (resourceAccess != null && resourceAccess.containsKey(KEYCLOAK_CLIENT_ID_WITH_USER_ROLES)) {
                Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(KEYCLOAK_CLIENT_ID_WITH_USER_ROLES);
                if (clientAccess != null && clientAccess.containsKey("roles")) {
                    List<String> clientRoles = (List<String>) clientAccess.getOrDefault("roles", Collections.emptyList());
                    if (!clientRoles.isEmpty()) {
                        logger.info("Roles de cliente encontrados para {}: {}", KEYCLOAK_CLIENT_ID_WITH_USER_ROLES, clientRoles);
                        return clientRoles.stream()
                                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                                .collect(Collectors.toList());
                    }
                }
            }
        } catch (ClassCastException e) {
            logger.debug("resource_access structure unexpected: {}", e.getMessage());
        }

        // 2. Buscar roles en realm_access (Roles de Reino)
        try {
            Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                List<String> realmRoles = (List<String>) realmAccess.getOrDefault("roles", Collections.emptyList());
                if (!realmRoles.isEmpty()) {
                    logger.info("Roles de reino encontrados: {}", realmRoles);
                    return realmRoles.stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                            .collect(Collectors.toList());
                }
            }
        } catch (ClassCastException e) {
            logger.debug("realm_access structure unexpected: {}", e.getMessage());
        }

        logger.info("No se encontraron roles en el token JWT");
        return Collections.emptyList();
    }
}
