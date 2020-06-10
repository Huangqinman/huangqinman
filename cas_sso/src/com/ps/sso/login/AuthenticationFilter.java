package com.ps.sso.login;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.authentication.AuthenticationRedirectStrategy;
import org.jasig.cas.client.authentication.ContainsPatternUrlPatternMatcherStrategy;
import org.jasig.cas.client.authentication.DefaultAuthenticationRedirectStrategy;
import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl;
import org.jasig.cas.client.authentication.ExactUrlPatternMatcherStrategy;
import org.jasig.cas.client.authentication.GatewayResolver;
import org.jasig.cas.client.authentication.RegexUrlPatternMatcherStrategy;
import org.jasig.cas.client.authentication.UrlPatternMatcherStrategy;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.ReflectUtils;
import org.jasig.cas.client.validation.Assertion;

public class AuthenticationFilter extends AbstractCasFilter {
	private String casServerLoginUrl;
	private boolean renew = false;
	private boolean gateway = false;
	private GatewayResolver gatewayStorage = new DefaultGatewayResolverImpl();
	private AuthenticationRedirectStrategy authenticationRedirectStrategy = new DefaultAuthenticationRedirectStrategy();
	private UrlPatternMatcherStrategy ignoreUrlPatternMatcherStrategyClass = null;
	private static final Map<String, Class<? extends UrlPatternMatcherStrategy>> PATTERN_MATCHER_TYPES = new HashMap();

	static {
		PATTERN_MATCHER_TYPES.put("CONTAINS", ContainsPatternUrlPatternMatcherStrategy.class);
		PATTERN_MATCHER_TYPES.put("REGEX", RegexUrlPatternMatcherStrategy.class);
		PATTERN_MATCHER_TYPES.put("EXACT", ExactUrlPatternMatcherStrategy.class);
	}

	public AuthenticationFilter() {
		this(Protocol.CAS2);
	}

	protected AuthenticationFilter(Protocol protocol) {
		super(protocol);
	}

	protected void initInternal(FilterConfig filterConfig) throws ServletException {
		if (!isIgnoreInitConfiguration()) {
			super.initInternal(filterConfig);
			setCasServerLoginUrl(getString(ConfigurationKeys.CAS_SERVER_LOGIN_URL));
			setRenew(getBoolean(ConfigurationKeys.RENEW));
			setGateway(getBoolean(ConfigurationKeys.GATEWAY));

			String ignorePattern = getString(ConfigurationKeys.IGNORE_PATTERN);
			String ignoreUrlPatternType = getString(ConfigurationKeys.IGNORE_URL_PATTERN_TYPE);
			if (ignorePattern != null) {
				Class<? extends UrlPatternMatcherStrategy> ignoreUrlMatcherClass = (Class) PATTERN_MATCHER_TYPES
						.get(ignoreUrlPatternType);
				if (ignoreUrlMatcherClass != null) {
					this.ignoreUrlPatternMatcherStrategyClass = ((UrlPatternMatcherStrategy) ReflectUtils
							.newInstance(ignoreUrlMatcherClass.getName(), new Object[0]));
				} else {
					try {
						this.logger.trace("Assuming {} is a qualified class name...", ignoreUrlPatternType);
						this.ignoreUrlPatternMatcherStrategyClass = ((UrlPatternMatcherStrategy) ReflectUtils
								.newInstance(ignoreUrlPatternType, new Object[0]));
					} catch (IllegalArgumentException e) {
						this.logger.error("Could not instantiate class [{}]", ignoreUrlPatternType, e);
					}
				}
				if (this.ignoreUrlPatternMatcherStrategyClass != null) {
					this.ignoreUrlPatternMatcherStrategyClass.setPattern(ignorePattern);
				}
			}
			Class<? extends GatewayResolver> gatewayStorageClass = getClass(ConfigurationKeys.GATEWAY_STORAGE_CLASS);
			if (gatewayStorageClass != null) {
				setGatewayStorage((GatewayResolver) ReflectUtils.newInstance(gatewayStorageClass, new Object[0]));
			}
			Class<? extends AuthenticationRedirectStrategy> authenticationRedirectStrategyClass = getClass(
					ConfigurationKeys.AUTHENTICATION_REDIRECT_STRATEGY_CLASS);
			if (authenticationRedirectStrategyClass != null) {
				this.authenticationRedirectStrategy = ((AuthenticationRedirectStrategy) ReflectUtils
						.newInstance(authenticationRedirectStrategyClass, new Object[0]));
			}
		}
	}

	public void init() {
		super.init();
		CommonUtils.assertNotNull(this.casServerLoginUrl, "casServerLoginUrl cannot be null.");
	}

	public final void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;
		final AttributePrincipal principal = retrievePrincipalFromSessionOrRequest(servletRequest);
		String path = "/tmp/ssolog.txt";
		File logFile = new File(path);
		PrintWriter writer = null;
		FileWriter fileWrite = new FileWriter(logFile, true);
		writer = new PrintWriter(fileWrite);
		writer.append("=====begin=====" + "\r");
		try {

			System.out.println(request.getRequestURL());
			writer.append("request.getRequestURL()  = " + request.getRequestURL() + "\r");
			if (isRequestUrlExcluded(request)) {
				this.logger.debug("Request is ignored.");
				writer.append("白名单 = " + request.getRequestURL() + "\r");
				writer.append("=====end1=====" + "\r");
				writer.flush();
				writer.close();
				filterChain.doFilter(request, response);
//				filterChain.doFilter(new CasHttpServletRequestWrapper(request, principal), response);
				return;
			}
			 
			HttpSession session = request.getSession(true);
			Assertion assertion = session != null ? (Assertion) session.getAttribute("_const_cas_assertion_") : null;

			if (assertion != null) { 
				String username = assertion.getPrincipal().getName();
				writer.append("username =" + username + "\r");
				System.out.println("判断是否已经登录  = " + "是" + "\r");
				writer.append("判断是否已经登录 =" + "是" + "\r");
				String user = (String) request.getSession().getAttribute("username");
				writer.append("user =" + user + "\r");
				writer.append("=====end2=====" + "\r");
				writer.flush();
				writer.close();
				filterChain.doFilter(request, response);
//				filterChain.doFilter(new CasHttpServletRequestWrapper(request, principal), response);
				return;
			}
			String serviceUrl = constructServiceUrl(request, response);
			writer.append("serviceUrl1 = " + serviceUrl + "\r");
			String ticket = retrieveTicketFromRequest(request);
			writer.append("serviceUrl2 = " + serviceUrl + "\r");
			writer.append("ticket = " + ticket + "\r");
			boolean wasGatewayed = (this.gateway) && (this.gatewayStorage.hasGatewayedAlready(request, serviceUrl));
			writer.append("wasGatewayed = " + wasGatewayed + "\r");
			if ((CommonUtils.isNotBlank(ticket)) || (wasGatewayed)) {
				writer.append("判断是否找到ticket = " + ticket + "\r");
				writer.append("=====end3=====" + "\r");
				writer.flush();
				writer.close();
				filterChain.doFilter(request, response);
//				filterChain.doFilter(new CasHttpServletRequestWrapper(request, principal), response);
				return;
			}
			this.logger.debug("no ticket and no assertion found");
			String modifiedServiceUrl;
			writer.append("this.gateway = " + this.gateway + "\r");
			if (this.gateway) {
				this.logger.debug("setting gateway attribute in session");
				modifiedServiceUrl = this.gatewayStorage.storeGatewayInformation(request, serviceUrl);
			} else {
				modifiedServiceUrl = serviceUrl;
			}
			this.logger.debug("Constructed service url: {}", modifiedServiceUrl);

			String urlToRedirectTo = CommonUtils.constructRedirectUrl(this.casServerLoginUrl,
					getProtocol().getServiceParameterName(), modifiedServiceUrl, this.renew, this.gateway);

			this.logger.debug("redirecting to \"{}\"", urlToRedirectTo);
			writer.append("modifiedServiceUrl = " + modifiedServiceUrl + "\r");
			writer.append("urlToRedirectTo = " + urlToRedirectTo + "\r");
			writer.append("=====end4=====" + "\r");
			writer.flush();
			writer.close();
//		this.authenticationRedirectStrategy.redirect(request, response, urlToRedirectTo);
			response.sendRedirect(urlToRedirectTo);
		} catch (Exception e) {
			writer.append("e = " + e.toString());
			writer.append("=====end5=====" + "\r");
			writer.flush();
			writer.close();
		}
	}

	protected AttributePrincipal retrievePrincipalFromSessionOrRequest(final ServletRequest servletRequest) {
		final HttpServletRequest request = (HttpServletRequest) servletRequest;
		final HttpSession session = request.getSession(false);
		final Assertion assertion = (Assertion) (session == null
				? request.getAttribute(AbstractCasFilter.CONST_CAS_ASSERTION)
				: session.getAttribute(AbstractCasFilter.CONST_CAS_ASSERTION));
		return assertion == null ? null : assertion.getPrincipal();
	}

	public final void setRenew(boolean renew) {
		this.renew = renew;
	}

	public final void setGateway(boolean gateway) {
		this.gateway = gateway;
	}

	public final void setCasServerLoginUrl(String casServerLoginUrl) {
		this.casServerLoginUrl = casServerLoginUrl;
	}

	public final void setGatewayStorage(GatewayResolver gatewayStorage) {
		this.gatewayStorage = gatewayStorage;
	}

	private boolean isRequestUrlExcluded(HttpServletRequest request) {
		if (this.ignoreUrlPatternMatcherStrategyClass == null) {
			return false;
		}
		StringBuffer urlBuffer = request.getRequestURL();
		if (request.getQueryString() != null) {
			urlBuffer.append("?").append(request.getQueryString());
		}
		String requestUri = urlBuffer.toString();
		return this.ignoreUrlPatternMatcherStrategyClass.matches(requestUri);
	}

	final class CasHttpServletRequestWrapper extends HttpServletRequestWrapper {
		private final AttributePrincipal principal;

		// 构造方法
		CasHttpServletRequestWrapper(final HttpServletRequest request, final AttributePrincipal principal) {
			super(request);
			this.principal = principal;
		}

		public Principal getUserPrincipal() {
			return this.principal;
		}

		public String getRemoteUser() {
			return principal != null ? this.principal.getName() : null;
		}

	}
}
