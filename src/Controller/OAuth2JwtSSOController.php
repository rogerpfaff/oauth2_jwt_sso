<?php

namespace Drupal\oauth2_jwt_sso\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\oauth2_jwt_sso\Authentication\Provider\OAuth2JwtSSOProvider;
use Drupal\user\Entity\User;
use Lcobucci\JWT\Parser;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

class OAuth2JwtSSOController extends ControllerBase {

  function authcodeLogin(Request $request) {
    $provider = new OAuth2JwtSSOProvider(\Drupal::configFactory(), [
      'redirectUri' => $GLOBALS['base_url'] . '/user/login/remote',
    ]);
    $code = $request->get('code');
    $state = $request->get('state');
    if ($code == NULL) {
      $authorizationUrl = $provider->getAuthorizationUrl();
      $_SESSION['oauth2state'] = $provider->getState();
      $response = TrustedRedirectResponse::create($authorizationUrl);

      return $response;
    }
    elseif (empty($state) || (isset($_SESSION['oauth2state']) && $state !== $_SESSION['oauth2state'])) {
      if (isset($_SESSION['oauth2state'])) {
        unset($_SESSION['oauth2state']);
      }
      throw new AccessDeniedHttpException('Invalid State');
    }
    else {
      try {
        $accessToken = $provider->getAccessToken('authorization_code', ['code' => $code]);
        $token = $accessToken->getToken();
        if ($provider->verifyToken($token)) {
          $token = (new Parser())->parse($token);
          $username = $token->getClaim('username');
          if (user_load_by_name($username)) {
            $user = user_load_by_name($username);
            user_login_finalize($user);

            return $this->redirect('<front>');
          }
          else {
            $user = User::create([
              'name' => $username,
              'mail' => 'test@test.com',
              'pass' => '',
              'status' => 1,
            ]);
            $user->save();
            user_login_finalize($user);

            return $this->redirect('<front>');
          }
        }
        else {
          throw new AccessDeniedHttpException('Invalid Token');
        }
      }
      catch (IdentityProviderException $e) {
        watchdog_exception('OAuth2 JWT SSO', $e, $e->getMessage(), [], E_ERROR);
        throw new AccessDeniedHttpException($e->getMessage());
      }
    }
  }

}
