package com.example.loginauthapi.infra.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    SecurityFilter securityFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize

                        //AuthController
                        .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/register").permitAll()

                        //machines
                        .requestMatchers(HttpMethod.POST, "/auth/registerMachine").permitAll()
                        .requestMatchers(HttpMethod.GET, "/auth/allMachines").permitAll()


                        //EstoqueInsumosController
                        .requestMatchers(HttpMethod.POST, "/estoque/insumos/adicionar").hasAnyRole("ControleEstoque", "admin")
                        .requestMatchers(HttpMethod.POST, "/estoque/insumos/atualizar/{id}").hasAnyRole("ControleEstoque", "admin")
                        .requestMatchers(HttpMethod.POST, "/estoque/insumos/{id}").hasAnyRole("ControleEstoque", "admin")


                        //EstoquePecasController
                        .requestMatchers(HttpMethod.POST, "/pecas/add").hasAnyRole("EstoquePecas", "admin")
                        .requestMatchers(HttpMethod.PATCH, "/pecas/preco").hasAnyRole("EstoquePecas", "admin")
                        .requestMatchers(HttpMethod.GET, "/pecas/listarPecas").hasAnyRole("EstoquePecas", "admin")
                        .requestMatchers(HttpMethod.PATCH, "/pecas/quantidade").hasAnyRole("EstoquePecas", "admin")
                        .requestMatchers(HttpMethod.DELETE, "/pecas/deletar").hasAnyRole("EstoquePecas", "admin")


                        //InventarioPecasController
                        .requestMatchers(HttpMethod.POST, "/inventario/add").hasAnyRole("InventarioPecas", "admin")
                        .requestMatchers(HttpMethod.GET, "/inventario/listar").hasAnyRole("InventarioPecas", "admin")
                        .requestMatchers(HttpMethod.DELETE, "/inventario/excluir").hasAnyRole("InventarioPecas", "admin")
                        .requestMatchers(HttpMethod.PATCH, "/inventario/lugar/alterar").hasAnyRole("InventarioPecas", "admin")
                        .requestMatchers(HttpMethod.GET, "/inventario/{id}").hasAnyRole("InventarioPecas","admin")


                        //RFIDController
                        .requestMatchers(HttpMethod.POST, "/rfid/create").hasAnyRole("RFID", "admin")
                        .requestMatchers(HttpMethod.GET, "/rfid/update").hasAnyRole("RFID", "admin")
                        .requestMatchers(HttpMethod.DELETE, "/rfid/{id}").hasAnyRole("RFID", "admin")
                        .requestMatchers(HttpMethod.GET, "/rfid/all").hasAnyRole("RFID", "admin")
                        .requestMatchers(HttpMethod.GET, "/rfid/delete/{id}").hasAnyRole("RFID", "admin")
                        .requestMatchers(HttpMethod.POST, "/localizacao/create").hasAnyRole("RFID", "admin")
                        .requestMatchers(HttpMethod.PUT, "/localizacao/update").hasAnyRole("RFID", "admin")
                        .requestMatchers(HttpMethod.GET, "/localizacao/{id}").hasAnyRole("RFID", "admin")
                        .requestMatchers(HttpMethod.GET, "/localizacao/all").hasAnyRole("RFID", "admin")
                        .requestMatchers(HttpMethod.GET, "/localizacao/{id}").hasAnyRole("RFID", "admin")


                        //CpfController
                        .requestMatchers(HttpMethod.POST, "/cpf").permitAll()


                        .requestMatchers("/gs-guide-websocket/**").permitAll() // Permitir acesso ao WebSocket endpoint
                        .anyRequest().authenticated()
                )
                .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}


