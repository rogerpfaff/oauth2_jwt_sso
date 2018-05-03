<?php

namespace Drupal\oauth2_jwt_sso\Authentication\Provider;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\oauth2_jwt_sso\Authentication\OAuth2JwtSSOResourceOwner;
use Drupal\user\Entity\User;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Keychain;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\ValidationData;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class OAuth2JwtSSOProvider extends AbstractProvider implements OAuth2JwtSSOProviderInterface {

  use BearerAuthorizationTrait;

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * @var \Symfony\Component\HttpFoundation\Session\SessionInterface
   */
  protected $session;

  /**
   * OAuth2JwtSSOProvider constructor.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   * @param \Symfony\Component\HttpFoundation\Session\SessionInterface $session
   * @param array $options
   * @param array $collaborators
   */
  public function __construct(ConfigFactoryInterface $configFactory, SessionInterface $session, array $options = [], array $collaborators = []) {
    $this->configFactory = $configFactory;
    $options['clientId'] = $this->configFactory->get('oauth2_jwt_sso.settings')
      ->get('client_id');
    $options['clientSecret'] = $this->configFactory->get('oauth2_jwt_sso.settings')
      ->get('client_secret');
    $this->session = $session;
    parent::__construct($options, $collaborators);
  }

  /**
   * {@inheritdoc}
   */
  public function getBaseAuthorizationUrl() {
    return $this->configFactory->get('oauth2_jwt_sso.settings')
      ->get('authorization_url');
  }

  /**
   * {@inheritdoc}
   */
  public function getBaseAccessTokenUrl(array $params) {
    return $this->configFactory->get('oauth2_jwt_sso.settings')
      ->get('access_token_url');
  }

  public function getResourceOwnerDetailsUrl(AccessToken $token) {
    // TODO: Implement getResourceOwnerDetailsUrl() method.
  }

  public function getDefaultScopes() {
    if($this->configFactory->get('oauth2_jwt_sso.settings')->get('roles_remote_login')){
      return array_values($this->configFactory->get('oauth2_jwt_sso.settings')->get('roles_remote_login'));
    }
  }

  protected function getScopeSeparator(){
    return " ";
  }

  public function applies(Request $request) {
    return $this->hasToken($request);
  }

  public static function hasToken(Request $request) {
    $auth_header = trim($request->headers->get('Authorization', '', TRUE));

    return strpos($auth_header, 'Bearer ') !== FALSE;
  }

  public function authenticate(Request $request) {
    $signer = new Sha256();
    $keychain = new Keychain();
    $auth_header = trim($request->headers->get('Authorization', '', TRUE));
    $token_str = substr($auth_header, 7);
    $token = (new Parser())->parse($token_str);
    $public_key = $this->configFactory->get('oauth2_jwt_sso.settings')
      ->get('auth_public_key');
    $validateData = new ValidationData();
    $verifyToken = $token->verify($signer, $keychain->getPublicKey($public_key));
    $validateToken = $token->validate($validateData);
    if ($verifyToken && $validateToken) {
      $username = $token->getClaim('username');
      $account = user_load_by_name($username);
      if ($account) {
        $this->session->set('sso-token', $token_str);
        return $account;
      }
      else {
        try {
          $account = User::create(['name' => $username, 'status' => 1]);
          $account->save();
          $this->session->set('sso-token', $token_str);
          return $account;
        }
        catch (\Exception $e) {
          watchdog_exception('OAuth2 JWT SSO', $e);

          return [];
        }

      }
    }
    else {
      \Drupal::logger('OAuth2 JWT SSO')->warning('Invalidate JWT Token.');

      return [];
    }
  }

  public function verifyToken(string $token) {
    $signer = new Sha256();
    $keychain = new Keychain();
    $token = (new Parser())->parse($token);
    $public_key = $this->configFactory->get('oauth2_jwt_sso.settings')
      ->get('auth_public_key');
    $token_claims = $token->getClaims();
    $custom_verify = TRUE;
    \Drupal::moduleHandler()
      ->alter('SSO_verify_token_alter', $custom_verify, $token_claims);

    return ($token->verify($signer, $keychain->getPublicKey($public_key)) && $custom_verify);
  }

  public function createUser(AccessToken $access_token){
    $token_str = $access_token->getToken();
    if($this->verifyToken($token_str)){
      $token = (new Parser())->parse($token_str);
      $username = $token->getClaim('username');
      $roles = $token->getClaim('scopes');
      if (user_load_by_name($username)) {
        $user = user_load_by_name($username);
      }
      else{
        $user = User::create([
          'name' => $username,
          'mail' => $username . '@' . $username . '.com',
          'pass' => NULL,
          'status' => 1,
        ]);
        foreach($roles as $role) {
          if ($role != 'authenticated') {
            $user->addRole($role);
          }
        }
        $user->save();
      }

      $this->session->set('sso-token', $token_str);
      return $user;
    }
    return False;
  }

  /**
   * Check a provider response for errors.
   *
   * @param \Psr\Http\Message\ResponseInterface $response
   * @param array|string $data
   *
   * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException
   */
  protected function checkResponse(ResponseInterface $response, $data) {
    if ($response->getStatusCode() >= 400) {
      throw new IdentityProviderException(
        $data['error'] ? : $response->getReasonPhrase(),
        $response->getStatusCode(),
        $response
      );
    }
  }

  protected function createResourceOwner(array $response, AccessToken $token) {

    return new OAuth2JwtSSOResourceOwner($response, $token);
  }

}
