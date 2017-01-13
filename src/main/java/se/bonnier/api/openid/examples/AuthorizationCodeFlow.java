package se.bonnier.api.openid.examples;

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
import se.bonnier.api.openid.entity.OAuthAuthorizationRequestAccessType;
import se.bonnier.api.openid.exceptions.BonnierOpenIdException;
import se.bonnier.api.openid.response.OAuth2Response;
import se.bonnier.api.openid.util.SplusUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Properties;

/**
 * Created by rene on 20/12/16.
 */
public class AuthorizationCodeFlow {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationCodeFlow.class);

    private static final Properties props = new Properties();
    private static final String fileName = "authorizationcodeflow.conf";
    private static final int localServerPort = 9090;

    private static BipAuthorizationCodeFlowClient ssoClient;
    private static String authorizationRequestUri;
    private static String logoutRequestUri;
    private static String clientId;
    private static String clientSecret;
    private static String scope;
    private static String redirectUri;
    private static String postLogoutRedirectUri;
    private static String accountId;
    private static String state;

    private static String accessToken;
    private static String firstname;
    private static String lastname;

    public static void main( String[] args) throws Exception {
        readConfigFile();

        String endpoint = props.getProperty("bip.endpoint");
        clientId = props.getProperty("bip.client.id");
        clientSecret = props.getProperty("bip.client.secret");
        redirectUri = props.getProperty("bip.redirect.uri");
        postLogoutRedirectUri = props.getProperty("bip.post.logout.redirect.uri");
        authorizationRequestUri = props.getProperty("bip.authorization.request.uri");
        logoutRequestUri = props.getProperty("bip.logout.request.uri");

        accountId = "74SiK5PSzADFjeZ0CXJWTM";
        scope = "openid email profile appId:di.se";

        accessToken = firstname = lastname = null;

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

    private static Server initServer() {
        Server server = new Server(localServerPort);
        ContextHandler contextRoot = new ContextHandler("/");
        contextRoot.setHandler(new RootPage());
        ContextHandler contextBipHandler = new ContextHandler("/bipHandler");
        contextBipHandler.setHandler(new BipHandler());
        ContextHandler contextLogout = new ContextHandler("/bipLogout");
        contextLogout.setHandler(new BipLogout());

        ContextHandlerCollection contexts = new ContextHandlerCollection();
        contexts.setHandlers(new Handler[] { contextRoot, contextBipHandler, contextLogout });
        server.setHandler(contexts);

        return server;
    }

    public static class RootPage extends AbstractHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
            state = SplusUtil.createOpenIdState();
            response.setContentType("text/html; charset=utf-8");
            response.setStatus(HttpServletResponse.SC_OK);
            PrintWriter out = response.getWriter();
            if(accessToken == null) {
                String loginUrl = ssoClient.getAuthorizeUrl(authorizationRequestUri, clientId, redirectUri, scope, state,
                        null, null, "sv", null, null);
                out.println("<h2>Welcome !</h2>");
                out.println("You are not logged in yet ! Please click <a href='" + loginUrl + "'>here</a> to login");
            } else {
                String logoutUrl = ssoClient.getLogoutUrl(logoutRequestUri, "di.se", postLogoutRedirectUri, state);
                out.println("<h2>Welcome " + firstname + " " + lastname + " !</h2>");
                out.println("You are logged in ! Click <a href='" + logoutUrl + "'>here</a> to logout.");
            }

            baseRequest.setHandled(true);
        }
    }

    public static class BipHandler extends AbstractHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
            response.setContentType("text/html; charset=utf-8");

            String returnState = request.getParameter("state");
            if (returnState == null || !returnState.equals(state)) {
                LOGGER.error("Error ! State doesn't match !");
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

                        OAuth2Response result = ssoClient.requestAccessToken(clientId,
                                clientSecret,
                                code,
                                redirectUri,
                                longLivedToken,
                                null);

                        LOGGER.debug("Success getting access token : " + result.accessToken);
                        LOGGER.debug("Token type : " + result.tokenType);
                        LOGGER.debug("Expires in : " + result.expiresIn);
                        LOGGER.debug("Refresh token : " + result.refreshToken);

                        ClaimsSet claimsSet = ssoClient.verifyIdToken(result.idToken, clientId);
                        accountId = claimsSet.getClaim("sub").toString();
                        String firstName = claimsSet.getClaim("given_name").toString();
                        String lastName = claimsSet.getClaim("family_name").toString();

                        LOGGER.debug("ID token : {accountId:" + accountId + ",firstName:" + firstName + ",lastName:" + lastName + "}");

                        accessToken = result.accessToken;
                        firstname = firstName;
                        lastname = lastName;

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
                accessToken = firstname = lastname = null;
                LOGGER.info("User logout successful !");

                response.setContentLength(0);
                response.sendRedirect("http://localhost:" + localServerPort);
            }
        }
    }
}
