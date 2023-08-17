package telran.spring.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import telran.spring.security.jwt.JwtFilter;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class SecurityConfiguration {

	final JwtFilter jwtFilter;
	final AuthorizationConfiguration authorizationConfiguration;

	@Bean
	@Order(5)
	SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http.cors(custom -> custom.disable()).csrf(custom -> custom.disable())
				.authorizeHttpRequests(custom -> custom.requestMatchers("/login").permitAll().requestMatchers(HttpMethod.OPTIONS).permitAll());
		authorizationConfiguration.configure(http);
		log.info("Filter with JWToken - configured and loaded");
		return http.httpBasic(Customizer.withDefaults())
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class).build();
		
	}
}