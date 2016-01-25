package se.bonnier.api.openid.util;

import org.jose4j.keys.BigEndianBigInteger;
import org.jose4j.keys.EcKeyUtil;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;

/**
 * @author kien.nguyen
 */
public class JwsKeys {
    // The ECDSA key consists of a public part, the EC point (x, y)
    public static final int[] X_INTS_256 = {127, 205, 206, 39, 112, 246, 196, 93, 65, 131, 203,
            238, 111, 219, 75, 123, 88, 7, 51, 53, 123, 233, 239,
            19, 186, 207, 110, 60, 123, 209, 84, 69};
    public static final int[] Y_INTS_256 =  {199, 241, 68, 205, 27, 189, 155, 126, 135, 44, 223,
            237, 185, 238, 185, 244, 179, 105, 93, 110, 169, 11,
            36, 173, 138, 70, 35, 40, 133, 136, 229, 173};

    public static final byte[] X_BYTES_256 = ByteUtil.convertUnsignedToSignedTwosComp(X_INTS_256);
    public static final byte[] Y_BYTES_256 = ByteUtil.convertUnsignedToSignedTwosComp(Y_INTS_256);

    public static final BigInteger X_256 = BigEndianBigInteger.fromBytes(X_BYTES_256);
    public static final BigInteger Y_256 = BigEndianBigInteger.fromBytes(Y_BYTES_256);


    public static ECPublicKey PUBLIC_256 = null;


    // The ECDSA key consists of a public part, the EC point (x, y)
    public static final int[] X_INTS_521 = {1, 233, 41, 5, 15, 18, 79, 198, 188, 85, 199, 213,
            57, 51, 101, 223, 157, 239, 74, 176, 194, 44, 178,
            87, 152, 249, 52, 235, 4, 227, 198, 186, 227, 112,
            26, 87, 167, 145, 14, 157, 129, 191, 54, 49, 89, 232,
            235, 203, 21, 93, 99, 73, 244, 189, 182, 204, 248,
            169, 76, 92, 89, 199, 170, 193, 1, 164};
    public static final int[] Y_INTS_521 = {0, 52, 166, 68, 14, 55, 103, 80, 210, 55, 31, 209,
            189, 194, 200, 243, 183, 29, 47, 78, 229, 234, 52,
            50, 200, 21, 204, 163, 21, 96, 254, 93, 147, 135,
            236, 119, 75, 85, 131, 134, 48, 229, 203, 191, 90,
            140, 190, 10, 145, 221, 0, 100, 198, 153, 154, 31,
            110, 110, 103, 250, 221, 237, 228, 200, 200, 246};

    public static final byte[] X_BYTES_521 = ByteUtil.convertUnsignedToSignedTwosComp(X_INTS_521);
    public static final byte[] Y_BYTES_521 = ByteUtil.convertUnsignedToSignedTwosComp(Y_INTS_521);

    public static final BigInteger X_521 = BigEndianBigInteger.fromBytes(X_BYTES_521);
    public static final BigInteger Y_521 = BigEndianBigInteger.fromBytes(Y_BYTES_521);


    public static ECPublicKey PUBLIC_521 = null;

    static
    {
        EcKeyUtil ecKeyUtil = new EcKeyUtil();

        try
        {
            PUBLIC_256 = ecKeyUtil.publicKey(X_256, Y_256, EllipticCurves.P256);
            PUBLIC_521 = ecKeyUtil.publicKey(X_521, Y_521, EllipticCurves.P521);
        }
        catch (JoseException e)
        {
            LoggerFactory.getLogger(JwsKeys.class).warn("Unable to initialize Example EC keys.", e);
        }
    }
}
