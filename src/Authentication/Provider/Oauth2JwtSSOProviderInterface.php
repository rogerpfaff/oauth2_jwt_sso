<?php
namespace Drupal\oauth2_jwt_sso\Authentication\Provider;

use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Symfony\Component\HttpFoundation\Request;

interface Oauth2JwtSSOProviderInterface extends AuthenticationProviderInterface {

  public static function hasToken(Request $request);
}
