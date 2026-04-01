package com.tcc.projeto.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtro JWT que intercepta todas as requisições e valida o token Bearer.
 * Executado uma única vez por requisição.
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsServiceImpl servicoDetalhesUsuario;

    public JwtAuthFilter(JwtUtil jwtUtil, UserDetailsServiceImpl servicoDetalhesUsuario) {
        this.jwtUtil = jwtUtil;
        this.servicoDetalhesUsuario = servicoDetalhesUsuario;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest requisicao,
                                    HttpServletResponse resposta,
                                    FilterChain cadeiaFiltros)
            throws ServletException, IOException {

        String cabecalhoAutorizacao = requisicao.getHeader("Authorization");

        // Verifica se o cabeçalho tem um token Bearer
        if (cabecalhoAutorizacao == null || !cabecalhoAutorizacao.startsWith("Bearer ")) {
            cadeiaFiltros.doFilter(requisicao, resposta);
            return;
        }

        String token = cabecalhoAutorizacao.substring(7);
        String nomeUsuario = null;

        try {
            nomeUsuario = jwtUtil.extrairNomeUsuario(token);
        } catch (Exception e) {
            // Token inválido — deixa passar sem autenticar
            cadeiaFiltros.doFilter(requisicao, resposta);
            return;
        }

        // Se extraiu nomeUsuario e o contexto não está autenticado ainda
        if (nomeUsuario != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails detalhesUsuario = servicoDetalhesUsuario.loadUserByUsername(nomeUsuario);

            if (jwtUtil.validarToken(token, detalhesUsuario)) {
                UsernamePasswordAuthenticationToken tokenAutenticacao =
                        new UsernamePasswordAuthenticationToken(
                                detalhesUsuario, null, detalhesUsuario.getAuthorities());
                tokenAutenticacao.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(requisicao));
                SecurityContextHolder.getContext().setAuthentication(tokenAutenticacao);
            }
        }

        cadeiaFiltros.doFilter(requisicao, resposta);
    }
}
