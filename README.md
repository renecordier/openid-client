# openid-client
Usage:
```java
//contact S+ to get token endpoint
//TODO using open id discovery
String endpoint = "https://api.devtest.newsplus.se/v1/oauth2";
SplusOpenIdClient client = new SplusOpenIdClient(endpoint);
try {
    OAuth2Response response = client.requestAccessToken(String clientId,
            String clientSecret,
            String scope,
            String grantType,
            String code,
            String redirectURI);
   String accessToken = response.accessToken;
} catch(BonnierOpenIdException e) {
 
} catch(Exception e) {
 
}
```
