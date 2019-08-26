package dev.utils;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import dev.domains.User;
import dev.exceptions.AppException;

public class DbUtils {

	private static final String DATABASE_URL = "jdbc:mysql://localhost:3307/top_securite_bdd?characterEncoding=UTF-8";
	private static final String DATABASE_USER = "root";
	private static final String DATABASE_PASS = "root";

	public User resultSetToUser(ResultSet rs) {
		try {
			return new User(rs.getInt("id"), rs.getString("firstname"), rs.getString("lastname"), rs.getString("login"),
					rs.getString("password"), rs.getBoolean("is_admin"));
		} catch (SQLException e) {
			throw new AppException(e);
		}
	}

	public <T> List<T> executeSelect(String sql, Function<ResultSet, T> fn, String[] values) {

		List<T> list = new ArrayList<>();

		try (Connection connection = DriverManager.getConnection(DATABASE_URL, DATABASE_USER, DATABASE_PASS);
				PreparedStatement statement = connection.prepareStatement(sql)) {

			for (int i = 0; i < values.length; i++) {
				statement.setString(i + 1, values[i]);
			}
			try (ResultSet rs = statement.executeQuery();) {
				while (rs.next()) {
					list.add(fn.apply(rs));
				}
			}

		} catch (SQLException e) {
			throw new AppException(e);
		}

		return list;
	}

	public void executeInsert(String sql, String[] values) {
		try (Connection connection = DriverManager.getConnection(DATABASE_URL, DATABASE_USER, DATABASE_PASS);
				PreparedStatement ps = connection.prepareStatement(sql)) {
			for (int i = 0; i < values.length; i++) {
				ps.setString(i + 1, values[i]);
			}
			ps.executeUpdate();

		} catch (SQLException e) {
			throw new AppException(e);
		}

	}
}
