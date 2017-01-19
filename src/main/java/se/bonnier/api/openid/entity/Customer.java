package se.bonnier.api.openid.entity;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.xc.JaxbAnnotationIntrospector;

import java.io.IOException;
import java.io.Serializable;

/**
 * Created by rene on 18/01/17.
 */
public class Customer implements Serializable {

    private String id;
    private String email;
    private String firstname;
    private String lastname;
    private String accessToken;
    private String refreshToken;
    private String idToken;
    private boolean loggedIn = false;
    private boolean remembered;


    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public boolean isLoggedIn() {
        return loggedIn;
    }

    public void setLoggedIn(boolean loggedIn) {
        this.loggedIn = loggedIn;
    }

    public boolean isRemembered() {
        return remembered;
    }

    public void setRemembered(boolean remembered) {
        this.remembered = remembered;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String token) {
        this.refreshToken = token;
    }

    public String getIdToken() {
        return idToken;
    }

    public void setIdToken(String token) {
        this.idToken = token;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String toJson() {
        ObjectMapper jsonMapper = new ObjectMapper();
        JaxbAnnotationIntrospector introspector = new JaxbAnnotationIntrospector();
        jsonMapper.getSerializationConfig().setAnnotationIntrospector(introspector);

        try {
            return jsonMapper.writeValueAsString(this);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
