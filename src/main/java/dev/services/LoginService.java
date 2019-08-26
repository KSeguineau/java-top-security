package dev.services;

import java.util.List;
import java.util.Optional;

import at.favre.lib.crypto.bcrypt.BCrypt;
import dev.domains.User;
import dev.exceptions.AppException;
import dev.utils.DbUtils;

public class LoginService {

	public Optional<User> connect(String login, String password) {
		String[] values = { login };
		List<User> results = new DbUtils().executeSelect(String.format("select * from user where login=?"),
				resultSet -> new DbUtils().resultSetToUser(resultSet), values);

		if (results.size() > 1) {
			throw new AppException("at least 2 users with same login");
		}

		return results.stream().findAny();
	}

	public boolean verifyPassword(String pClair, String pHash) {
		return BCrypt.verifyer().verify(pClair.toCharArray(),
				pHash).verified;
	}

}
