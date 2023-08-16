package telran.spring.security.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import telran.spring.security.jwt.model.LoginData;
import telran.spring.security.jwt.model.LoginResponse;

@RestController
@RequestMapping("/login")
@RequiredArgsConstructor
@CrossOrigin
public class JwtController {
	
	final UserDetailsService userDetailService;
	final PasswordEncoder passwordEncoder;
	final JwtUtil jwtUtils;
	@PostMapping
	LoginResponse login(@RequestBody @Valid LoginData loginData) {
		try {
			String username = loginData.email();
			String password = loginData.password();
			UserDetails userDetails = userDetailService.loadUserByUsername(username);	
			if(userDetails == null || !userDetails.isAccountNonExpired()){
				throw new UsernameNotFoundException("Account with username: " + username + " not found");
			}
			if(!passwordEncoder.matches(password, userDetails.getPassword())) {
				throw new IllegalArgumentException("Wrong credentials");
			}
			return new LoginResponse(jwtUtils.createJWToken(userDetails));
			
		} catch (UsernameNotFoundException e) {
			throw new IllegalArgumentException("Wrong credentials: "+ e.getMessage());
		}
			
	}

}
