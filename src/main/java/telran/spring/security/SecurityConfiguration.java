package telran.spring.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;
import telran.spring.security.jwt.JwtFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {

	final JwtFilter jwtFilter;
	final AuthorizationConfiguration authorizationConfiguration;

	@Bean
	@Order(5)
	SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http.cors(custom -> custom.disable()).csrf(custom -> custom.disable())
				.authorizeHttpRequests(custom -> custom.requestMatchers("/login").permitAll());
		authorizationConfiguration.configure(http);
		return http.httpBasic(Customizer.withDefaults())
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class).build();
	}
}