package se.bonnier.api.openid.exceptions;

/**
 * Created by vietnq2 on 11/17/15.
 */
public class BonnierOpenIdException extends RuntimeException {
    public BonnierOpenIdException(Exception e) {
        super(e);
    }
    public BonnierOpenIdException(String message) {
        super(message);
    }
}
