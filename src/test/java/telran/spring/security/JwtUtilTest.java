package telran.spring.security;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import org.assertj.core.util.Arrays;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.User;
import org.springframework.test.context.TestPropertySource;

import io.jsonwebtoken.ExpiredJwtException;
import telran.spring.security.jwt.JwtUtil;

@SpringBootTest(classes = {JwtUtil.class})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JwtUtilTest {
	
	@Autowired
	JwtUtil jwtUtil;
	
	static String jwtToken;
	static final String USER_NAME = "user";
	static String[] expectedRoles = {"ADMIN"}; 
	
	@Test
	@Order(1)
	void creationJwt() {
		jwtToken = jwtUtil.createJWToken(User.withUsername(USER_NAME)
				.password(USER_NAME)
				.roles("ADMIN").build());
	}
	
	@Test
	@Order(2)
	void extractUserName() {
		assertEquals(USER_NAME, jwtUtil.extractUserName(jwtToken));
	}
	
	@Test
	@Order(3)
	void extractRoles() {
		assertIterableEquals(Arrays.asList(expectedRoles), jwtUtil.extractRoles(jwtToken));
	}
	
	@Test
	void expirationTest() throws InterruptedException {
		Thread thread = new Thread();
			thread.sleep(2500);
			assertThrowsExactly(ExpiredJwtException.class, () -> jwtUtil.extractUserName(jwtToken));
		
	}
	
	

}
