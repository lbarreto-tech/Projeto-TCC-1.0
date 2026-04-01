package com.tcc.projeto.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * Configuração de segurança da aplicação.
 * - Rotas públicas liberadas sem autenticação
 * - Rotas /api/admin/** protegidas por JWT
 * - CORS liberado para o frontend
 * - Sessão sem estado (JWT)
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthFilter filtroJwt;
    private final UserDetailsServiceImpl servicoDetalhesUsuario;

    public SecurityConfig(JwtAuthFilter filtroJwt,
                          UserDetailsServiceImpl servicoDetalhesUsuario) {
        this.filtroJwt = filtroJwt;
        this.servicoDetalhesUsuario = servicoDetalhesUsuario;
    }

    @Bean
    public SecurityFilterChain cadeiaFiltroSeguranca(HttpSecurity http) throws Exception {
        http
                // Desabilita CSRF (usamos JWT, não cookies de sessão)
                .csrf(csrf -> csrf.disable())

                // Configuração de CORS
                .cors(cors -> cors.configurationSource(fonteConfiguracaoCors()))

                // Configuração de autorização por rota
                .authorizeHttpRequests(autorizacao -> autorizacao
                        // Rotas totalmente públicas
                        .requestMatchers(HttpMethod.POST, "/api/agendamentos").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/agendamentos/datas-disponiveis").permitAll()
                        // Login do admin é público
                        .requestMatchers(HttpMethod.POST, "/api/autenticacao/login").permitAll()
                        // Qualquer rota /api/admin/** requer autenticação
                        .requestMatchers("/api/admin/**").authenticated()
                        // Nega qualquer outra rota não mapeada
                        .anyRequest().denyAll()
                )

                // Sem sessão — sem estado com JWT
                .sessionManagement(sessao ->
                        sessao.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Provedor de autenticação
                .authenticationProvider(provedorAutenticacao())

                // Adiciona o filtro JWT antes do filtro padrão de autenticação
                .addFilterBefore(filtroJwt, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Configuração de CORS — libera o frontend para fazer chamadas à API.
     * Ajuste o allowedOrigins para o domínio real do frontend em produção.
     */
    @Bean
    public CorsConfigurationSource fonteConfiguracaoCors() {
        CorsConfiguration configuracao = new CorsConfiguration();
        // Em produção, substitua "*" pelo domínio real: "https://meusite.com.br"
        configuracao.setAllowedOriginPatterns(List.of("*"));
        configuracao.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuracao.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
        configuracao.setAllowCredentials(true);
        configuracao.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource fonte = new UrlBasedCorsConfigurationSource();
        fonte.registerCorsConfiguration("/**", configuracao);
        return fonte;
    }

    @Bean
    public AuthenticationProvider provedorAutenticacao() {
        DaoAuthenticationProvider provedor = new DaoAuthenticationProvider();
        provedor.setUserDetailsService(servicoDetalhesUsuario);
        provedor.setPasswordEncoder(codificadorSenha());
        return provedor;
    }

    @Bean
    public AuthenticationManager gerenciadorAutenticacao(
            AuthenticationConfiguration configuracao) throws Exception {
        return configuracao.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder codificadorSenha() {
        return new BCryptPasswordEncoder();
    }
}

