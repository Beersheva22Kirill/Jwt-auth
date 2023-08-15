package telran.spring.security.jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {
	
	
	
	@Value("${app.jwt.signature.secret}")
	//For when you just want a random 256 bit 32 Byte Hex.
	String key;
	@Value("${app.security.token.expiration.period:3600000}")
	long expPeriod;
	
	public String extractUserName(String token) {
		
		return extractClaim(token, Claims :: getSubject);
	};
	
	public Date extractExpirationDate(String token) {
		
		return extractClaim(token, Claims :: getExpiration);
	}
	
	public List<String> extractRoles(String token) {
		
		return (List<String>) extractClaim(token, claims -> claims.get("roles"));
	}
	
	public Claims extractAllClaims(String token) {
		
		return Jwts.parserBuilder().setSigningKey(getSignInKey()).build()
					.parseClaimsJws(token).getBody();
	}

	private Key getSignInKey() {
		byte[] keyBytes = Decoders.BASE64.decode(key);
		
		return Keys.hmacShaKeyFor(keyBytes);
	}
	
	public <T> T extractClaim(String token,Function<Claims, T> claimResolver) {
		
		return claimResolver.apply(extractAllClaims(token));
	};
	
	
	public String createJWToken(UserDetails userDetails) {
		
		return createJWToken(new HashMap<>(), userDetails);
	}
	
	public String createJWToken(Map<String, Object> extraClaims, UserDetails userDetails) {
		String[] roles = userDetails.getAuthorities().stream()
				.map(auth -> auth.getAuthority().replace("ROLE_", "")).toArray(String[]::new);
		extraClaims.put("roles", roles);
		Date current = new Date();
		Date exp = new Date(current.getTime() + expPeriod);
		return Jwts.builder().addClaims(extraClaims).setExpiration(exp).setIssuedAt(current)
				.setSubject(userDetails.getUsername()).signWith(getSignInKey(),SignatureAlgorithm.HS256).compact();
	}

}
