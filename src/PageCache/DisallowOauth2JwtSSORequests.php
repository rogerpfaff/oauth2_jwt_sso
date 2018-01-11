<?php

namespace Drupal\oauth2_jwt_sso\PageCache;

use Drupal\Core\PageCache\RequestPolicyInterface;
use Drupal\oauth2_jwt_sso\Authentication\Provider\Oauth2JwtSSOProvider;
use Symfony\Component\HttpFoundation\Request;

class DisallowOauth2JwtSSORequests implements RequestPolicyInterface {

  public function check(Request $request) {
    return Oauth2JwtSSOProvider::hasToken($request) ? self::DENY : NULL;
  }
}
