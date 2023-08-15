package telran.spring.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface AuthorizationConfiguration {
	void configure (HttpSecurity httpSecurity) throws Exception;

}
