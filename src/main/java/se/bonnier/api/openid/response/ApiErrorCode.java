package se.bonnier.api.openid.response;

/**
 *
 * @author jonas.vis
 */
public enum ApiErrorCode {
    TOKEN_EXPIRED,
    UNAUTHORIZED_SCOPE,
    INVALID_REQUEST,
    NOT_FOUND,
    INVALID_DATA,
    ALREADY_EXISTS,
    UNAUTHORIZED,
    OTHER_ERROR,
    CLIENT_ACTIVATION_PERIOD_EXPIRED,
    CONCURRENT_EXCEEDED
}
