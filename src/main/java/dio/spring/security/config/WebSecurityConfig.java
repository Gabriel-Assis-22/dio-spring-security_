package dio.spring.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true) // Anotação atualizada para segurança de método
public class WebSecurityConfig {

    // Injeção de dependência via campo (não em método de configuração)
    @Autowired
    private SecurityDatabaseService securityService;

    // Configuração do PasswordEncoder como um Bean
    @Bean
    public PasswordEncoder passwordEncoder() {
        // Use um encoder de senha moderno. NoOpPasswordEncoder é obsoleto e inseguro.
        // O código original usava {noop}, então vamos manter NoOp para não quebrar a lógica,
        // mas em produção, use BCryptPasswordEncoder.
        return NoOpPasswordEncoder.getInstance();
    }

    // Define o SecurityFilterChain como um Bean para configurar as regras de autorização
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/").permitAll()
                        .requestMatchers(HttpMethod.POST, "/login").permitAll()
                        .requestMatchers("/managers").hasAnyRole("MANAGERS")
                        .requestMatchers("/users").hasAnyRole("USERS", "MANAGERS")
                        .anyRequest().authenticated()
                )
                .httpBasic(withDefaults());

        return http.build();
    }
}