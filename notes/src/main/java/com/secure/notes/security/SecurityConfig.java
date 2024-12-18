package com.secure.notes.security;

import com.secure.notes.config.OAuth2LoginSuccessHandler;
import com.secure.notes.models.AppRole;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.repositories.UserRepository;
import com.secure.notes.security.jwt.AuthEntryPointJwt;
import com.secure.notes.security.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.jaas.memory.InMemoryConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;

import java.beans.Encoder;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

//define own custom configuration
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true) //to enable Method-level security
public class SecurityConfig {
    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Autowired
    @Lazy
    OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;

    @Value("${frontend.url}")
    private String frontendUrl;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter(){
        return new AuthTokenFilter();
    }


//    @Autowired
//    CustomLoggingFilter customLoggingFilter;

    //taken from SpringBootWebSecurityConfiguration
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        //The code enables CSRF protection by storing the CSRF token in a cookie (accessible to JavaScript) to allow frontend frameworks to include it in requests for validation.
        http.csrf(csrf ->
                csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers("/api/auth/public/**") // configures the application to disable CSRF protection for any endpoints that match the pattern
        );

        //Enabling Adding CORS

        http.cors(
                cors -> cors.configurationSource(corsConfigurationSource())
        );

        http.authorizeHttpRequests((requests) ->
                requests
//                        //Request matches is a method used in spring security to configure which HTTP request should match specific security rules.
//                        .requestMatchers("/contact").permitAll() //Making certain endpoints accessible/ to bypass the authentication for certain endpoints
//                        .requestMatchers("/public/**").permitAll() //in future also if you add any endpoints starting with slash public, then would it would bypass spring security.
//                        //a scenario wherein you wish to deny access to certain HTTP endpoints irrespective of their authentication status or roles.
//                        .requestMatchers("/admin").denyAll()

                        //to enable URL-Based security
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/csrf-token").permitAll()
                        .requestMatchers("/api/auth/public/**").permitAll()
                        .requestMatchers("/oauth2/**").permitAll()

                        .anyRequest().authenticated())
                        //Enable Oauth2 login
                        .oauth2Login(oauth2 -> {
                            oauth2.successHandler(oAuth2LoginSuccessHandler);
                        });

        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        //we want to desable csrf, to avoid Invalid CSRF token found for http://localhost:8080/api/notes
        //The error Invalid CSRF token occurs because Spring Security is enabled, and it expects a valid CSRF (Cross-Site Request Forgery) token in requests that modify data (like POST, PUT, or DELETE)
        //By default, Spring Security includes CSRF protection for state-changing requests to prevent malicious cross-origin actions.
//        http.csrf().disable();
//        http.csrf(csrf -> csrf.disable());
        http.csrf(AbstractHttpConfigurer::disable);

//        //Specifies that the application will not create or use HTTP sessions to manage authentication or state.
//        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        //Ordering the filter
//        http.addFilterBefore(new CustomLoggingFilter(), UsernamePasswordAuthenticationFilter.class);

//        http.addFilterAfter(new RequestValidationFilter(), CustomLoggingFilter.class);

        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    //Configuring multiple users Authentication using InMemoryAuthenticationProvider

//    @Bean
//    public UserDetailsService userDetailsService(){
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();

//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource){
//        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);
//
//        if(!manager.userExists("user1")){ //it does not exist
//            manager.createUser(
//                    User.withUsername("user1")
//                            .password("{noop}password1")  //{noop} The {noop} prefix in the password field indicates that the password is stored in plain text and no encoding is applied to it. This is used in Spring Security when you want to test or use a plain text password without applying any hashing or encoding.
//                            .roles("USER")
//                            .build()
//            );
//        }
//
////        if(!manager.userExists("admin")){
////            manager.createUser(
////                    User.withUsername("admin")
////                            .password("{noop}adminPass")
////                            .roles("ADMIN")
////                            .build()
////            );
////        }
//        UserDetails user2 = User.withUsername("admin")
//                                        .password("{noop}adminPass")
//                                        .roles("ADMIN")
//                                        .build();
//        if(!manager.userExists("admin")){
//            manager.createUser(user2);
//        }
//
//        return manager;
//    }


    //password encoders
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //Adding CORS
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        // Allow specific origins
        //corsConfig.setAllowedOrigins(Arrays.asList("http://localhost:3000", "https://shieldnotes.netlify.app"));
        //List<String> allowedOrigins = Arrays.asList(frontendUrl.split(","));
        //corsConfig.setAllowedOrigins(allowedOrigins);
        corsConfig.setAllowedOrigins(Collections.singletonList(frontendUrl));

        // Allow specific HTTP methods
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        // Allow specific headers
        corsConfig.setAllowedHeaders(Arrays.asList("*"));
        // Allow credentials (cookies, authorization headers)
        corsConfig.setAllowCredentials(true);
        corsConfig.setMaxAge(3600L);
        // Define allowed paths (for all paths use "/**")
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig); // Apply to all endpoints
        return source;
    }


    //some dummy user credentials

    @Bean
    public CommandLineRunner initData(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            Role userRole = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_USER)));

            Role adminRole = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_ADMIN)));

            if (!userRepository.existsByUserName("user1")) {
//                User user1 = new User("user1", "user1@example.com", "{noop}password1");
                User user1 = new User("user1", "user1@example.com", passwordEncoder.encode("password1"));
                user1.setAccountNonLocked(false);
                user1.setAccountNonExpired(true);
                user1.setCredentialsNonExpired(true);
                user1.setEnabled(true);
                user1.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                user1.setAccountExpiryDate(LocalDate.now().plusYears(1));
                user1.setTwoFactorEnabled(false);
                user1.setSignUpMethod("email");
                user1.setRole(userRole);
                userRepository.save(user1);
            }

            if (!userRepository.existsByUserName("admin")) {
                User admin = new User("admin", "admin@example.com", passwordEncoder.encode("adminPass"));
                admin.setAccountNonLocked(true);
                admin.setAccountNonExpired(true);
                admin.setCredentialsNonExpired(true);
                admin.setEnabled(true);
                admin.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                admin.setAccountExpiryDate(LocalDate.now().plusYears(1));
                admin.setTwoFactorEnabled(false);
                admin.setSignUpMethod("email");
                admin.setRole(adminRole);
                userRepository.save(admin);
            }
        };
    }
}

