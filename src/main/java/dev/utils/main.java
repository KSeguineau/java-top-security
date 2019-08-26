package dev.utils;

import at.favre.lib.crypto.bcrypt.BCrypt;

public class main {

	public main() {
		// TODO Auto-generated constructor stub
	}

	public static void main(String[] args) {
		String password = "admin";
		System.out.println(BCrypt.withDefaults().hashToString(12, password.toCharArray()));

		BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(),
				"$2a$12$QFYX2f/bhL9MQ86lCOyAkuy9dZyiGjQs/FHek0YzGkX71PJOwQxXm");
		System.out.println(result.verified);

		System.out.println(System.getenv("KEY_HMAC"));
	}

}
