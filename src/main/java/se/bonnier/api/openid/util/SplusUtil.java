package se.bonnier.api.openid.util;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by vietnq2 on 11/17/15.
 */
public class SplusUtil {
    public static String createOpenIdState() {
        String state = new BigInteger(130, new SecureRandom()).toString(32);
        return state;
    }
}
