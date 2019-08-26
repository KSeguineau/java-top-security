package dev.controllers.auth.utils;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;

import javax.servlet.http.Cookie;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;

import dev.domains.User;

public class LoginUtils {

	public LoginUtils() {
		// TODO Auto-generated constructor stub
	}

	public Cookie createCookie(User user) {

		StringBuilder sb = new StringBuilder();

		String message = sb.append(user.getFirstname()).append(";").append(user.getLastname()).append(";")
				.append(user.getLogin()).append(";").append(user.getAdmin()).append(";").append(LocalDateTime.now()
						.toString())
				.toString();
		String messageEncode = Base64.getEncoder().encodeToString(message.getBytes());

		String signature = new HmacUtils(HmacAlgorithms.HMAC_SHA_512, System.getenv("KEY_HMAC")).hmacHex(messageEncode);
		Cookie cookie = new Cookie("utilisateur", messageEncode + "|" + new String(signature));
		cookie.setHttpOnly(true);
		return cookie;

	}

	public boolean verifyCookieIntegrity(Cookie cookie) {
		String[] cookieValue = cookie.getValue().split("\\|");
		String messageEncode = cookieValue[0];
		String signature = cookieValue[1];

		return verifySignature(messageEncode, signature);

	}

	private boolean verifySignature(String messageEncode, String signature) {

		boolean validationSignature = new HmacUtils(HmacAlgorithms.HMAC_SHA_512, System.getenv("KEY_HMAC")).hmacHex(
				messageEncode).equals(signature);
		String message = message = new String(Base64.getDecoder().decode(messageEncode.getBytes()));
		String heure = message.split(";")[4];

		boolean tempsValiditer = verifyDate(LocalDateTime.parse(heure));
		return validationSignature && tempsValiditer;
	}

	private boolean verifyDate(LocalDateTime dateInitial) {
		LocalDateTime now = LocalDateTime.now();
		Duration duration = Duration.between(dateInitial, now);

		return duration.getSeconds() < 600;
	}

	public User createUser(Cookie cookie) {
		String[] cookieValue = cookie.getValue().split("\\|");
		String messageEncode = cookieValue[0];
		String message = message = new String(Base64.getDecoder().decode(messageEncode.getBytes()));
		String[] userValues = message.split(";");
		User user = new User(userValues[0], userValues[1]);
		user.setLogin(userValues[2]);
		user.setAdmin(Boolean.valueOf(userValues[3]));

		return user;
	}
}
