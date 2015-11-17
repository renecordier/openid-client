package se.bonnier.api.openid.response;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.List;

/**
 *
 * @author jonas.vis
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class OAuth2Response {
    
    @XmlElement(name = "access_token")
    public String accessToken;
    
    @XmlElement(name = "token_type")
    public String tokenType;
    
    @XmlElement(name = "expires_in")
    public Integer expiresIn;
    
    @XmlElement(name = "refresh_token")
    public String refreshToken;
    
    // Optional
    @XmlElement(name = "search_token")
    public List<String> searchToken;

    @XmlElement(name = "id_token")
    public String idToken;
    
    @XmlElement
    public String scope;
    
    @XmlAttribute
    public Integer httpResponseCode;
    
    @XmlAttribute
    public String requestId;
    
    @XmlElement
    public String code;

    @XmlElement
    public String state;
    

    // Error fields
    
    @XmlElement
    public String error;

    @XmlElement(name = "error_uri")
    public String errorUri;
  
    @XmlAttribute
    public ApiErrorCode errorCode;
  
    @XmlElement
    public String errorMsg;

     
}
