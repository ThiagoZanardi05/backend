package com.pin.config; // Verifique se o package está correto

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.List; // Adicionado para Arrays.asList
import java.util.Arrays; // Adicionado para Arrays.asList

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        logger.info(">>> Configurando SecurityFilterChain...");
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Usando a bean para CORS
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> {
                    logger.info(">>> Configurando authorizeHttpRequests...");
                    authz
                            .requestMatchers(HttpMethod.GET, "/api/user/findAll").hasRole("ADMIN")
                            .requestMatchers(HttpMethod.POST, "/api/user/create").hasRole("ADMIN")
                            .requestMatchers(HttpMethod.GET, "/api/item/findAll").hasAnyRole("USER", "ADMIN")
                            .requestMatchers(HttpMethod.GET, "/api/grupo/findAll").hasAnyRole("USER", "ADMIN")
                            .requestMatchers("/api/evento/**").hasAnyRole("USER", "ADMIN")
                            .anyRequest().authenticated();
                    logger.info(">>> Regras de authorizeHttpRequests configuradas.");
                })
                .oauth2ResourceServer(oauth2 -> {
                    logger.info(">>> Configurando oauth2ResourceServer...");
                    oauth2.jwt(jwt -> {
                        logger.info(">>> Configurando JWT para oauth2ResourceServer...");
                        jwt.jwtAuthenticationConverter(jwtAuthenticationConverter());
                        logger.info(">>> jwtAuthenticationConverter configurado para JWT.");
                    });
                    logger.info(">>> oauth2ResourceServer configurado.");
                });
        logger.info(">>> SecurityFilterChain construído.");
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        logger.info(">>> Bean jwtAuthenticationConverter está sendo criada e configurada.");

        // Conversor que usa a lógica manual, que sabemos que funciona.
        Converter<Jwt, Collection<GrantedAuthority>> manualAuthoritiesConverter = jwt -> {
            logger.info(">>> [MANUAL CONVERTER] Entrando para o JWT ID: {}, Claims: {}", jwt.getId(), jwt.getClaims());
            Collection<GrantedAuthority> authorities = Collections.emptyList();

            try {
                if (jwt.hasClaim("realm_access")) {
                    Object realmAccessClaim = jwt.getClaim("realm_access");
                    if (realmAccessClaim instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> realmAccessMap = (Map<String, Object>) realmAccessClaim;
                        if (realmAccessMap.containsKey("roles")) {
                            Object rolesClaim = realmAccessMap.get("roles");
                            if (rolesClaim instanceof Collection) {
                                @SuppressWarnings("unchecked")
                                Collection<String> roles = (Collection<String>) rolesClaim;
                                authorities = roles.stream()
                                        .map(role -> {
                                            logger.info(">>> [MANUAL CONVERTER] Mapeando role de realm_access: '{}' para 'ROLE_{}'", role, role.toUpperCase());
                                            return new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()); // Adiciona "ROLE_" e converte para MAIÚSCULAS
                                        })
                                        .collect(Collectors.toList());
                                logger.info(">>> [MANUAL CONVERTER] Authorities extraídas: {}",
                                        authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
                            } else {
                                logger.warn(">>> [MANUAL CONVERTER] 'realm_access.roles' não é uma Collection. Tipo: {}", (rolesClaim != null ? rolesClaim.getClass().getName() : "null"));
                            }
                        } else {
                            logger.warn(">>> [MANUAL CONVERTER] 'realm_access' não contém 'roles'. Keys: {}", realmAccessMap.keySet());
                        }
                    } else {
                        logger.warn(">>> [MANUAL CONVERTER] 'realm_access' não é um Map. Tipo: {}", (realmAccessClaim != null ? realmAccessClaim.getClass().getName() : "null"));
                    }
                } else {
                    logger.warn(">>> [MANUAL CONVERTER] JWT não possui a claim 'realm_access'. Claims: {}", jwt.getClaims().keySet());
                }
            } catch (Exception e) {
                logger.error(">>> [MANUAL CONVERTER] Erro ao extrair roles: ", e);
            }
            return authorities; // Retorna as authorities extraídas manualmente (ou lista vazia se falhar)
        };

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(manualAuthoritiesConverter); // Usa o conversor manual
        jwtAuthenticationConverter.setPrincipalClaimName(JwtClaimNames.SUB);

        logger.info(">>> Bean jwtAuthenticationConverter configurada com conversor MANUAL de authorities.");
        return jwtAuthenticationConverter;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200")); // Seu frontend Angular
        configuration.setAllowedMethods(Arrays.asList("GET","POST", "PUT", "DELETE", "OPTIONS", "PATCH")); // Adicione PATCH se usar
        configuration.setAllowedHeaders(Arrays.asList("*")); // Pode ser mais específico: "Authorization", "Content-Type", etc.
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        logger.info(">>> Bean CorsConfigurationSource configurada.");
        return source;
    }
}