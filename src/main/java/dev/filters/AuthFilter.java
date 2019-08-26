package dev.filters;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import dev.controllers.auth.utils.LoginUtils;
import dev.domains.User;

@WebFilter("/*")
public class AuthFilter implements Filter {

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {

	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) servletRequest;
		HttpServletResponse resp = (HttpServletResponse) servletResponse;
		LoginUtils loginUtils = new LoginUtils();
		boolean connected = false;

		Optional<Cookie> cookieOpt = Arrays.asList(req.getCookies()).stream().filter(c -> c.getName().equals(
				"utilisateur")).findFirst();

		if (cookieOpt.isPresent()) {
			Cookie cookie = cookieOpt.get();
			connected = loginUtils.verifyCookieIntegrity(cookie);
			User connectedUser = loginUtils.createUser(cookie);
			req.setAttribute("connectedUser", connectedUser);

		}

		if (connected || req.getRequestURI().contains("/login")) {
			filterChain.doFilter(servletRequest, servletResponse);
		} else {
			resp.sendRedirect(req.getContextPath() + "/login");
		}
	}

	@Override
	public void destroy() {

	}
}
