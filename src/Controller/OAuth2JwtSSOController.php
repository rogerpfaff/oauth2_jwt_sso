<?php

namespace Drupal\oauth2_jwt_sso\Controller;

use Lcobucci\JWT\Parser;
use Drupal\user\Entity\User;
use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\HttpFoundation\Request;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Drupal\oauth2_jwt_sso\Authentication\Provider\OAuth2JwtSSOProvider;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class OAuth2JwtSSOController extends ControllerBase implements ContainerInjectionInterface{

  /**
   * The configuration object factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * @var \Symfony\Component\HttpFoundation\Session\SessionInterface
   */
  protected $session;

  /**
   * Constructs a OAuth2JwtSSOController object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The configuration object factory.
   */
  public function __construct(ConfigFactoryInterface $config_factory, SessionInterface $session) {
    $this->configFactory = $config_factory;
    $this->session = $session;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('config.factory'),
      $container->get('session')
    );
  }

  function authcodeLogin(Request $request) {
    $remote_login_roles = $this->configFactory
      ->get('oauth2_jwt_sso.settings')
      ->get('roles_remote_login');
    $provider = new OAuth2JwtSSOProvider($this->configFactory, $request->getSession(), [
      'redirectUri' => $GLOBALS['base_url'] . '/user/login/remote',
      'scope' => implode(' ', $remote_login_roles),
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
        if($user = $provider->createUser($accessToken)) {
          user_login_finalize($user);
          return $this->redirect('<front>');
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
