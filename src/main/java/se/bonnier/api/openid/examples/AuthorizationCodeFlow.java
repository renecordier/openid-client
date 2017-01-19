package se.bonnier.api.openid.examples;

import org.codehaus.jettison.json.JSONObject;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.bonnier.api.openid.client.BipAuthorizationCodeFlowClient;
import se.bonnier.api.openid.entity.ClaimsSet;
import se.bonnier.api.openid.entity.Customer;
import se.bonnier.api.openid.entity.OAuthAuthorizationRequestAccessType;
import se.bonnier.api.openid.exceptions.BonnierOpenIdException;
import se.bonnier.api.openid.response.OAuth2Response;
import se.bonnier.api.openid.util.SplusUtil;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLDecoder;
import java.util.Properties;
import java.util.UUID;

/**
 * Created by rene on 20/12/16.
 */
public class AuthorizationCodeFlow {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationCodeFlow.class);

    private static final Properties props = new Properties();
    private static final String fileName = "authorizationcodeflow.conf";
    private static final int localServerPort = 9090;
    private static boolean isPublicClient;
    private static final String codeChallengeMethod = "plain";

    private static String codeChallenge;

    private static BipAuthorizationCodeFlowClient ssoClient;
    private static String authorizationRequestUri;
    private static String logoutRequestUri;
    private static String clientId;
    private static String clientSecret;
    private static String scope;
    private static String redirectUri;
    private static String postLogoutRedirectUri;
    private static String state;

    private static String bipUrl;
    private static Customer customer;

    public static void main( String[] args) throws Exception {
        cleanLoginSession();
        readConfigFile();

        String endpoint = props.getProperty("bip.endpoint");
        clientId = props.getProperty("bip.client.id");
        clientSecret = props.getProperty("bip.client.secret");
        redirectUri = props.getProperty("bip.redirect.uri");
        postLogoutRedirectUri = props.getProperty("bip.post.logout.redirect.uri");
        isPublicClient = Boolean.parseBoolean(props.getProperty("bip.client.is.public"));

        scope = "openid email profile appId:di.se";
        cleanLoginSession();

        //Example on using discovery endpoint
        String discoveryUrl = props.getProperty("bip.discovery.endpoint");
        JSONObject jsonDiscoveryConfig = BipAuthorizationCodeFlowClient.getOpenIdConfiguration(discoveryUrl);
        bipUrl = jsonDiscoveryConfig.getString("issuer");
        authorizationRequestUri = jsonDiscoveryConfig.getString("authorization_endpoint");
        logoutRequestUri = jsonDiscoveryConfig.getString("end_session_endpoint");

        if(clientId.equals("ENTER_HERE") || clientSecret.equals("ENTER_HERE")) {
            LOGGER.error("Please fill the needed values in the configuration file (src/main/resources/authorizationcodeflow.conf) given by S+ team after " +
                    "registering your BIP client");
            throw new BonnierOpenIdException("Missing values in config file !");
        }

        ssoClient = new BipAuthorizationCodeFlowClient(endpoint,clientId,clientSecret);

        Server server = initServer();
        server.start();

        LOGGER.info("The server is running at http://localhost:" + localServerPort);

        server.join();
    }

    private static void readConfigFile() {
        FileReader fr = null;
        try {
            File globalProps = new File("./src/main/resources/" + fileName);
            fr = new FileReader(globalProps);
            props.load(fr);
        } catch (Exception e) {
            LOGGER.error("Could not read config file: " + e.getMessage());
            throw new BonnierOpenIdException("Could not read config file");
        } finally {
            try {
                if (fr != null) {
                    fr.close();
                }
            } catch (Exception e) {
            }
        }
    }

    private static boolean isLoggedIn() {
        return customer == null ? false : customer.isLoggedIn();
    }

    private static Server initServer() {
        Server server = new Server(localServerPort);
        ContextHandler contextRoot = new ContextHandler("/");
        contextRoot.setHandler(new RootPage());
        ContextHandler contextBipHandler = new ContextHandler("/bipHandler");
        contextBipHandler.setHandler(new BipHandler());
        ContextHandler contextLogout = new ContextHandler("/bipLogout");
        contextLogout.setHandler(new BipLogout());
        ContextHandler contextRefreshToken = new ContextHandler("/bipRefresh");
        contextRefreshToken.setHandler(new BipRefreshToken());
        ContextHandler contextUserInfo = new ContextHandler("/bipUserInfo");
        contextUserInfo.setHandler(new BipUserInfo());
        ContextHandler contextRpIframe = new ContextHandler("/rp_iframe");
        contextRpIframe.setHandler(new RpIframe());
        ContextHandler contextSessionLoginHandler = new ContextHandler("/login-handler");
        contextSessionLoginHandler.setHandler(new SessionLoginHandler());

        ContextHandlerCollection contexts = new ContextHandlerCollection();
        contexts.setHandlers(new Handler[] { contextRoot, contextBipHandler, contextLogout, contextRefreshToken, contextUserInfo,
                contextRpIframe, contextSessionLoginHandler});
        server.setHandler(contexts);

        return server;
    }

    public static class RootPage extends AbstractHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
            response.setContentType("text/html; charset=utf-8");
            response.setStatus(HttpServletResponse.SC_OK);
            baseRequest.setHandled(true);

            state = SplusUtil.createOpenIdState();
            PrintWriter out = response.getWriter();
            out.println("<!DOCTYPE html>");
            out.println("<head><script type=\"text/javascript\" src=\"" + bipUrl + "/assets/bip-client.js\"></script></head>");
            out.println("<body>");

            String loginUrl = ssoClient.getAuthorizeUrl(authorizationRequestUri, clientId, redirectUri,
                    scope, state, null, null, "sv", null, null,
                    codeChallenge, isPublicClient ? codeChallengeMethod : null);
            String logoutUrl = ssoClient.getLogoutUrl(logoutRequestUri, "di.se", postLogoutRedirectUri, state);

            if(!isLoggedIn()) {
                if(isPublicClient) {
                    codeChallenge = UUID.randomUUID().toString();
                }
                out.println("<h2>Welcome !</h2>");
                out.println("<p>You are not logged in yet ! Please click <a id='login-link' href='" + loginUrl + "'>here</a> to login</p>");
            } else {
                out.println("<h2>Welcome " + customer.getFirstname() + " " + customer.getLastname() + " !</h2>");
                out.println("<p>You are logged in ! Click <a id='login-link' href='" + logoutUrl + "'>here</a> to logout.</p>");
                out.println("<p>To refresh token : click <a href='http://localhost:" + localServerPort + "/bipRefresh'>here</a> !</p>");
                out.println("<p>To check more user info, click <a href='http://localhost:" + localServerPort + "/bipUserInfo'>here</a> !</p>");
            }
            bipSessionManagementJs(out, loginUrl, logoutUrl);
            out.println("</body>");
        }
    }

    private static void bipSessionManagementJs(PrintWriter out, String loginUrl, String logoutUrl) {
        out.println("<script type=\"text/javascript\">\n" +
                "    function receiveMessage(e)\n" +
                "    {\n" +
                "        var logoutUrl=\"" + logoutUrl +"\";\n" +
                "        var loginUrl =\"" + loginUrl + "\";\n" +
                "        var data = JSON.parse(e.data);\n" +
                "        var loginlink = document.getElementById('login-link');\n" +
                "        if('true'== data.IsLoggedIn){\n" +
                "           loginlink.setAttribute('href',logoutUrl);\n" +
                "           loginlink.innerHTML = 'logout';\n" +
                "        }else{\n" +
                "           loginlink.setAttribute('href',loginUrl);\n" +
                "           loginlink.innerHTML = 'login';\n" +
                "        }\n" +
                "    }\n" +
                "    Bip.initialize({'op':'" + bipUrl + "/bip/check_session_iframe',\n" +
                "        'rp':'http://localhost:9090/rp_iframe',\n" +
                "        'client_id':'" + clientId +"',\n" +
                "        'frequency':'5',// in second\n" +
                "        'onMessage':receiveMessage\n" +
                "    });\n" +
                "\n" +
                "</script>");
    }

    public static class BipHandler extends AbstractHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
            response.setContentType("text/html; charset=utf-8");

            String returnState = request.getParameter("state");
            if (returnState == null || !returnState.equals(state)) {
                LOGGER.error("Error ! State doesn't match ! [state=" + state + "; returnState=" + returnState + "]");
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            } else {
                String code = request.getParameter("code");
                if (code != null) {
                    try {
                        String accessType = request.getParameter("access_type");
                        boolean longLivedToken = false;
                        if(accessType != null && accessType.equals(OAuthAuthorizationRequestAccessType.REMEMBER.toString())){
                            longLivedToken = true;
                        }

                        OAuth2Response tokenResponse;
                        if(isPublicClient) {
                            tokenResponse = ssoClient.requestAccessTokenWithPKCE(clientId,
                                    code,
                                    redirectUri,
                                    longLivedToken,
                                    codeChallenge);
                        } else {
                            tokenResponse = ssoClient.requestAccessToken(clientId,
                                    clientSecret,
                                    code,
                                    redirectUri,
                                    longLivedToken);
                        }

                        LOGGER.debug("Success getting access token : " + tokenResponse.accessToken);
                        LOGGER.debug("Token type : " + tokenResponse.tokenType);
                        LOGGER.debug("Expires in : " + tokenResponse.expiresIn);
                        LOGGER.debug("Refresh token : " + tokenResponse.refreshToken);

                        ClaimsSet claimsSet = ssoClient.verifyIdToken(tokenResponse.idToken, clientId);
                        customer = new Customer();
                        customer.setId(claimsSet.getClaim("sub").toString());
                        customer.setLoggedIn(true);
                        customer.setAccessToken(tokenResponse.accessToken);
                        customer.setRefreshToken(tokenResponse.refreshToken);
                        customer.setRemembered("true".equals(false));
                        customer.setEmail(claimsSet.getClaim("email").toString());
                        customer.setIdToken(tokenResponse.idToken);
                        customer.setFirstname(claimsSet.getClaim("given_name").toString());
                        customer.setLastname(claimsSet.getClaim("family_name").toString());

                        LOGGER.debug("ID token : {accountId:" + customer.getId() + ",firstName:" + customer.getFirstname()
                                + ",lastName:" + customer.getLastname() + ", email:" + customer.getEmail() + "}");

                        response.setContentLength(0);
                        response.sendRedirect("http://localhost:" + localServerPort);
                    } catch (BonnierOpenIdException e) {
                        LOGGER.error("Error Bonnier OpenId exception : " + e.getMessage());
                        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    } catch (Exception e) {
                        LOGGER.error("Error exception : " + e.getMessage());
                        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    }
                } else {
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                }
            }
            baseRequest.setHandled(true);
        }
    }

    public static class BipLogout extends AbstractHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
            String returnState = request.getParameter("state");
            if (returnState == null || !returnState.equals(state)) {
                LOGGER.error("Error ! State doesn't match !");
                response.setContentType("text/html; charset=utf-8");
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            } else {
                cleanLoginSession();
                LOGGER.info("User logout successful !");

                response.setContentLength(0);
                response.sendRedirect("http://localhost:" + localServerPort);
            }
            baseRequest.setHandled(true);
        }
    }

    public static class BipRefreshToken extends AbstractHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
            LOGGER.info("Init refresh token !");

            try {
                OAuth2Response oauth2Response;
                if(isPublicClient) {
                    oauth2Response = ssoClient.refreshPublicAccessToken(customer.getRefreshToken(), null, clientId);
                } else {
                    oauth2Response = ssoClient.refreshAccessToken(customer.getRefreshToken(), null);
                }
                customer.setAccessToken(oauth2Response.accessToken);

                LOGGER.debug("Success refreshing to new access token : " + oauth2Response.accessToken);

                LOGGER.info("End refresh token !");
                response.setContentLength(0);
                response.sendRedirect("http://localhost:" + localServerPort);
            } catch (BonnierOpenIdException e) {
                LOGGER.error("Error Bonnier OpenId exception : " + e.getMessage());
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            } catch (Exception e) {
                LOGGER.error("Error exception : " + e.getMessage());
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            }
            baseRequest.setHandled(true);
        }
    }

    public static class BipUserInfo extends AbstractHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
            response.setContentType("text/html; charset=utf-8");
            try {
                JSONObject json = ssoClient.getUserInfo(customer.getAccessToken());

                response.setStatus(HttpServletResponse.SC_OK);
                PrintWriter out = response.getWriter();
                out.println("<h1>User info :</h1>");
                out.println("<p>Bip account ID : " + json.getString("sub") + "</p>");
                out.println("<p>Email : " + json.getString("email") + "</p>");
                out.println("<p>Email verified : " + json.getString("email_verified") + "</p>");
                out.println("<p>Name : " + json.getString("name") + "</p>");
                out.println("<p>Back to <a href='http://localhost:" + localServerPort + "'>main page</a> !");
            } catch (Exception e) {
                LOGGER.error("Error exception : " + e.getMessage());
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                PrintWriter out = response.getWriter();
                out.println("<h1>An error occured !</h1>");
                out.println(e.getStackTrace());
            }
            baseRequest.setHandled(true);
        }
    }

    public static class RpIframe extends AbstractHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
            LOGGER.debug("RP iframe");
            response.setContentType("text/html; charset=utf-8");
            response.setStatus(HttpServletResponse.SC_OK);
            PrintWriter out = response.getWriter();
            out.println("<html>\n" +
                    "<head>\n" +
                    "    <title>Relying Party - Session State Iframe</title>\n" +
                    "    <script src=\"" + bipUrl + "/assets/bip-client.js\"></script>\n" +
                    "    <script >\n" +
                    "        Bip.connect({debug:true,\n" +
                    "            scope:\"" + scope +  "\",\n" +
                    "            loginHandlerUri:'http://localhost:9090/login-handler',\n" +
                    "            interval:5\n" +
                    "        })\n" +
                    "    </script>\n" +
                    "</head>\n" +
                    "<body>\n" +
                    "<form id=\"bipForm\">\n" +
                    "    Bonnier News Identity\n" +
                    "</form>\n" +
                    "</body>\n" +
                    "</html>\n");
            baseRequest.setHandled(true);
        }
    }

    public static class SessionLoginHandler extends AbstractHandler {

        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
            LOGGER.debug("Session login handler");

            String jsonCallback = request.getParameter("jsonCallback");
            if(jsonCallback != null){
                response.setContentType("application/json; charset=utf-8");
            } else {
                response.setContentType("text/html; charset=utf-8");
                //TODO: redirect
            }

            try {
                String code = request.getParameter("code");
                String error = request.getParameter("error");
                String sessionState = request.getParameter("session_state");
                sessionState = sessionState != null ? URLDecoder.decode(sessionState,"UTF-8") : sessionState;
                Cookie sessionCookie = new Cookie("session_state", sessionState);
                if(sessionState != null) {
                    sessionCookie.setPath("/");
                    sessionCookie.setSecure(false);
                    sessionCookie.setHttpOnly(false);
                    sessionCookie.setMaxAge(2000000000);
                    response.addCookie(sessionCookie);
                }
                if (error != null) {
                    String errorDesc = request.getParameter("error_description");
                    LOGGER.error("Error: " + error + "! " + errorDesc);
                    if("login_required".equals(error)) {
                        cleanLoginSession();
                    }
                    if (jsonCallback != null) {
                        response.getWriter().println(jsonCallback + "({\"IsLoggedIn\":\"false\"})");
                        baseRequest.setHandled(true);
                        return;
                    }
                }

                if(customer != null && jsonCallback != null){
                    if(customer.getEmail() != null) {
                        LOGGER.info("User already logged in");
                        response.getWriter().println(jsonCallback + "({\"IsLoggedIn\":\"true\",\"email\":\"" + customer.getEmail() + "\"})");
                        baseRequest.setHandled(true);
                        return;
                    }
                }

                if (code != null) {
                    String redirectUri = "http://localhost:9090" + ((jsonCallback != null)? "/login-handler?jsonCallback=jsonpCallback" : "/bipHandler" );
                    OAuth2Response tokenResponse = ssoClient.requestAccessToken(clientId,
                            clientSecret,
                            code,
                            redirectUri,
                            false);

                    ClaimsSet claimsSet = ssoClient.verifyIdToken(tokenResponse.idToken, clientId);
                    customer = new Customer();
                    customer.setId(claimsSet.getClaim("sub").toString());
                    customer.setLoggedIn(true);
                    customer.setAccessToken(tokenResponse.accessToken);
                    customer.setRefreshToken(tokenResponse.refreshToken);
                    customer.setRemembered("true".equals(false));
                    customer.setEmail(claimsSet.getClaim("email").toString());
                    customer.setIdToken(tokenResponse.idToken);
                    customer.setFirstname(claimsSet.getClaim("given_name").toString());
                    customer.setLastname(claimsSet.getClaim("family_name").toString());

                    LOGGER.debug("ID token : {accountId:" + customer.getId() + ",firstName:" + customer.getFirstname()
                            + ",lastName:" + customer.getLastname() + ", email:" + customer.getEmail() + "}");

                    if (jsonCallback != null) {
                        response.getWriter().println(jsonCallback + "({\"IsLoggedIn\":\"true\",\"email\":\"" + customer.getEmail() + "\"})");
                        baseRequest.setHandled(true);
                        return;
                    }

                }
            } catch (Exception e) {
                LOGGER.error(e.getMessage());
            }
            if (jsonCallback != null) {
                response.getWriter().println(jsonCallback + "({\"IsLoggedIn\":\"false\"})");
                baseRequest.setHandled(true);
                return;
            }
            response.setContentLength(0);
            response.sendRedirect("http://localhost:" + localServerPort);
            baseRequest.setHandled(true);
        }
    }

    private static void cleanLoginSession() {
        customer = null;
    }
}
