package telran.spring.security.jwt;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtFilter extends OncePerRequestFilter {
	
	private static final String AUTHORIAZATION_HEADER = "Authorization";
	private static final String BEARER = "Bearer ";
	final JwtUtil jwtUtil;
	final UserDetailsService userDetailsService;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)		
			throws ServletException, IOException {
			String jwtToken = getJwtToken(request);
			log.trace("Jwt from header is {} ",jwtToken == null ? "null" : jwtToken);
			if (jwtToken != null) {
				try {
					String userName = jwtUtil.extractUserName(jwtToken);
					UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
				log.trace("Extracted username is {}", userName);
					if(userDetails == null || !userDetails.isAccountNonExpired()) {
					throw new UsernameNotFoundException(userName);
				}
				UsernamePasswordAuthenticationToken authentification = new UsernamePasswordAuthenticationToken(userDetails,null, userDetails.getAuthorities());
				authentification.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authentification);
				log.trace("Security context is established");
				} catch (Throwable e) {
					log.error("Wrong credentials");
				}
				
			}
		filterChain.doFilter(request, response);	
		
	}

	private String getJwtToken(HttpServletRequest request) {
		String authHeader = request.getHeader(AUTHORIAZATION_HEADER);
		String res = null;
		if (authHeader != null && authHeader.startsWith(BEARER)) {
			res = authHeader.substring(BEARER.length());
		}
		return res;
	}

}
