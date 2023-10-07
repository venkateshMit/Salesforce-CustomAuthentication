/*
 * @description       : Generic Custom Auth Provider
 * @author            : Venkatesh Kulkarni
 * @group             : 
 * @last modified on  : 10-07-2023
**/


public with sharing class CustomAuthentication extends Auth.AuthProviderPluginClass {
    
    /** Constatns  */
    public static final String CUSTOM_METADATA_TYPE = 'Custom_Client_Credential_Flow__mdt';
    private IRefreshTokenGenerator generator = new DefaultRefreshTokenGenerator();

    /** 
     * Constructor
     */
    public CustomAuthentication() {}

    /** 
     * Parameterized Constructor which is used in Test class
     */
    public CustomAuthentication(IRefreshTokenGenerator gen) {
        this.generator = gen;
    }

    /** 
     * Overriding standard getCustomMetadataType method. 
     * The getCustomMetadataType method returns the custom metadata type API name for authentication provider.
     */
    public String getCustomMetadataType() {
        return CUSTOM_METADATA_TYPE;
    }

    /** 
     * Overriding standard initiate method. 
     * The initiate method returns the URL where the user is redirected for authentication
     */
    public PageReference initiate(Map< String, String > authProviderConfiguration, String stateToPropagate) {
        final String baseUrl = URL.getSalesforceBaseUrl().toExternalForm();
        final String url = baseUrl + '/services/authcallback/' + authProviderConfiguration.get('Auth_Provider__c') + '?state=' + stateToPropagate;
        return new PageReference(url);
    }

    /** 
     * Overriding standard handleCallback method. 
     * The handleCallback method returns an OAuth access token, OAuth secret or refresh token, and the state passed in when the request for the current user was initiated.
     */
    public Auth.AuthProviderTokenResponse handleCallback(Map < String, String > config, Auth.AuthProviderCallbackState callbackState) {
        // get access token
        final String access_token = this.retrieveToken(config);
        final String refresh_token = this.generateRefreshToken();
        final String state = callbackState.queryParameters.get('state');
        return new Auth.AuthProviderTokenResponse(config.get('Auth_Provider__c'), access_token, refresh_token, state);

    }
    /** 
     * Overriding standard getUserInfo method. 
     * The getUserInfo method returns information from the custom authentication provider about the current user.
     */
    public Auth.UserData getUserInfo(Map < String, String > authProviderConfiguration, Auth.AuthProviderTokenResponse response) {
        return new Auth.UserData(
            null,
            null,
            null,
            null,
            null,
            null,
            authProviderConfiguration.get('Auth_Provider__c') + '_' + 'User',
            null,
            authProviderConfiguration.get('Auth_Provider__c'),
            null,
            new Map < String, String > ()
        );
    }

    /** 
     * Overriding standard refresh method. 
     * The refresh method returns a new access token, which is used to update an expired access token.
     */
    public override Auth.OAuthRefreshResult refresh(Map < String, String > config, String refreshToken) {
        // generate dummy refresh token and get new access token
        final String newRefreshToken = this.generateRefreshToken();
        final String access_token = this.retrieveToken(config);
        system.debug('Refresh Method Called ****');
        return new Auth.OAuthRefreshResult(access_token, newRefreshToken);
    }

    /** 
     * This method calls the token api to retreive the token and send it as a String.
     */
    private String retrieveToken(Map < String, String > config) {
        final String tokenEndpoint = config.get('Token_Endpoint__c');
		String body;
        // setup request
        HttpRequest req = new HttpRequest();
        req.setEndpoint(tokenEndpoint);
        req.setMethod('POST');
        req.setHeader('Content-Type', 'application/x-www-form-urlencoded;charset=UTF-8');
        // Logic to seperate for setting up end point, headers, body for differrent Auth. Providers/Servers.
        if (config.get('Auth_Provider__c').containsIgnoreCase('OKTA')) {
            Blob blobValue = Blob.valueof(config.get('Client_ID__c') + ':' + config.get('Client_Secret__c'));
            String encodedString = EncodingUtil.base64Encode(blobValue);
            body = Constants.SCOPE + Constants.EQUAL + config.get('Scopes__c') + Constants.AMPERSAND +
                   Constants.GRANT_TYPE + Constants.EQUAL + config.get('Grant_Type__c');
            req.setHeader('Authorization', 'Basic {' + encodedString + '}');
           
        } else {

            body = Constants.CLIENT_ID + Constants.EQUAL + getAndEncode(config, 'Client_ID__c') + Constants.AMPERSAND +
                   Constants.CLIENT_SECRET + Constants.EQUAL + getAndEncode(config, 'Client_Secret__c') + Constants.AMPERSAND +
                   Constants.SCOPE + Constants.EQUAL + getAndEncode(config, 'Scopes__c') + Constants.AMPERSAND +
                   Constants.GRANT_TYPE + Constants.EQUAL + config.get('Grant_Type__c');
           
        }
        req.setBody(body);
        // execute requets
        Http h = new Http();
        HttpResponse res = h.send(req);

        // get token from response
        return this.getTokenFromHttpResponse(res);
    }

    /**
     * This Method Gets the access_token from Http response
     */
    private String getTokenFromHttpResponse(HttpResponse res) {
        final Map < String, Object > data = (Map < String, Object > ) JSON.deserializeUntyped(res.getBody());
        final String errorCode = (String) data.get('error');
        if (String.isNotEmpty(errorCode)) {
          	throw new Custom_ClientCredentials_Exception().setDetails(errorCode, (String) data.get('trace_id'), (String) data.get('correlation_id'),(String) data.get('errorSummary'),(String) data.get('errorLink'),(String) data.get('errorId'));
		} else {
             return (String) data.get(Constants.ACCESS_TOKEN);
        }
    }

    /**
     * This Method calls the generate method for the refresh token.
     */
    private String generateRefreshToken() {
        return this.generator.generate();
    }

    /**
     * Interface to allow us to override refresh token generation when testing.
     */
    public interface IRefreshTokenGenerator {
        String generate();
    }

    /**
     * Default implementation for runtime to generate the refresh Token.
     */
    public class DefaultRefreshTokenGenerator implements IRefreshTokenGenerator {
        public String generate() {
            final String refreshToken = EncodingUtil.base64Encode(Crypto.generateAesKey(128));
            return refreshToken;
        }
    }

    /**
     * This Method encodes the the value of the key and send it as response.
     */
    private String getAndEncode(Map < String, String > config, String key) {
        return EncodingUtil.urlEncode(config.get(key), Constants.UTF_8_ENCODING);
    }

      /**
     * This is a Exception Class for the AZure CLient credentails
     */
    public class Custom_ClientCredentials_Exception extends Exception {
        public String errorCode;
        public String traceId;
        public String correlationId;
        public String errorSummary;	
        public String errorLink;	
        public String errorId;
        public Custom_ClientCredentials_Exception setDetails(String error_code, String trace_id, String correlation_id,String errorSummary,String errorLink,String errorId) {
            this.traceId = trace_id;
            this.correlationId = correlation_id;
            this.errorCode = error_code;
            return this;
        }
    }
}