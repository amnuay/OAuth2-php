<?php
//https://oauth2-client.thephpleague.com/usage/
//composer require league/oauth2-client

require_once __DIR__.'/vendor/autoload.php';
session_start();
$provider = new \League\OAuth2\Client\Provider\GenericProvider([
	'scopes' =>'openid profile',
    'clientId'                => 'xxx',    // The client ID assigned to you by the provider
    //'clientSecret'          => 'xxx',    // The client password assigned to you by the provider
    'redirectUri'             => 'https://' . $_SERVER['HTTP_HOST'],
    'urlAuthorize'            => 'https://subdomain.onelogin.com/oidc/2/auth',
    'urlAccessToken'          => 'https://subdomain.onelogin.com/oidc/2/token',
    'urlResourceOwnerDetails' => 'https://subdomain.onelogin.com/oidc/2/me'
]);
if (isset($_REQUEST['logout'])) {
    unset($_SESSION['access_token']);
    unset($_SESSION['oauth2state']);
    $authUrl = $provider->getAuthorizationUrl();
    header('Location: '.$authUrl);
    exit;
}

// If we don't have an authorization code then get one
if (!isset($_GET['code'])) {

    // If we don't have an authorization code then get one
    $authUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->getState();
	  echo 'If we don have an authorization code then get one';
    header('Location: '.$authUrl);
  
// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {

   // unset($_SESSION['oauth2state']);
	  $authUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->getState();
	  echo 'If we don have an authorization code then get one';
    header('Location: '.$authUrl);
    exit('Invalid state, make sure HTTP sessions are enabled.');

} else {

       try {

        // Try to get an access token using the authorization code grant.
        $accessToken = $provider->getAccessToken('authorization_code', [
            'code' => $_GET['code']
        ]);

        // We have an access token, which we may use in authenticated
        // requests against the service provider's API.
        echo 'Access Token: ' . $accessToken->getToken() . "<br>";
        echo 'Refresh Token: ' . $accessToken->getRefreshToken() . "<br>";
        echo 'Expired in: ' . $accessToken->getExpires() . "<br>";
        echo 'Already expired? ' . ($accessToken->hasExpired() ? 'expired' : 'not expired') . "<br>";

        // Using the access token, we may look up details about the
        // resource owner.
        $resourceOwner = $provider->getResourceOwner($accessToken);
        var_export($resourceOwner->toArray());
		    $rsw = $resourceOwner->toArray();
        $_SESSION["userid"] = $rsw['sub'];
		    $_SESSION["preferred_username"] = $rsw['preferred_username'];
        // Redirect to page
		    //header("location: ");
		    exit;
        // The provider provides a way to get an authenticated API request for
        // the service, using the access token; it returns an object conforming
        // to Psr\Http\Message\RequestInterface.
        /*$request = $provider->getAuthenticatedRequest(
            'GET',
            'https://subdomain.onelogin.com/oidc/2/me',
            $accessToken
        );*/
		
			

    } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
        // Failed to get the access token or user details.
        exit($e->getMessage());

    }

}

?>
