package com.tcc.projeto.controller;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller de autenticação — público.
 * Emite tokens JWT para o administrador.
 */
@RestController
@RequestMapping("/api/autenticacao")
public class AuthController {

    private final AuthService servicoAutenticacao;

    public AuthController(AuthService servicoAutenticacao) {
        this.servicoAutenticacao = servicoAutenticacao;
    }

    /**
     * POST /api/autenticacao/login
     * Autentica o admin e retorna um token JWT.
     *
     * Body (JSON):
     * {
     *   "email": "admin@escola.gov.br",
     *   "senha": "suaSenha"
     * }
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @RequestBody @Valid LoginRequest requisicao) {

        AuthResponse autenticacao = servicoAutenticacao.login(requisicao);
        return ResponseEntity.ok(
                ApiResponse.sucesso("Login realizado com sucesso!", autenticacao));
    }
}
