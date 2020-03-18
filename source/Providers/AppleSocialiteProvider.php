<?php

namespace SeuAppAqui\Providers;

use Exceptions\InvalidTokenException;
use Illuminate\Http\Response;
use Illuminate\Support\Carbon;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;
use Illuminate\Support\Arr;

class AppleSocialiteProvider extends AbstractProvider implements ProviderInterface
{

  private const URL = 'https://appleid.apple.com';

  protected function getAuthUrl($state)
  {
    $this->buildAuthUrlFromBase(self::URL . "/auth/authorize", $state);
  }

  protected function getTokenUrl()
  {
    return self::URL . 'auth/token';
  }

  public function getAccessToken($code)
  {
    $response = $this->getHttpClient()
      ->post(
        $this->getTokenUrl(),
        [
          'headers' => [
            'Authorization' => 'Basic ' . base64_encode(
              $this->clientId . ':' . $this->clientSecret
            ),
          ],
          'body' => $this->getTokenFields($code),
        ]
      );

    return $this->parseAccessToken($response->getBody());
  }

  protected function parseAccessToken($response)
  {
    $data = $response->json();

    return $data['access_token'];
  }

  protected function getTokenFields($code)
  {
    $fields = parent::getTokenFields($code);
    $fields["grant_type"] = "authorization_code";

    return $fields;
  }

  public function user()
  {
    $response = $this->getAccessTokenResponse($this->getCode());

    $user = $this->mapUserToObject($this->getUserByToken(
      Arr::get($response, 'id_token')
    ));

    return $user
      ->setToken(Arr::get($response, 'access_token'))
      ->setRefreshToken(Arr::get($response, 'refresh_token'))
      ->setExpiresIn(Arr::get($response, 'expires_in'));
  }

  protected function getCodeFields($state = null)
  {
    $fields = [
      'client_id' => $this->clientId,
      'redirect_uri' => $this->redirectUrl,
      'scope' => $this->formatScopes($this->getScopes(), $this->scopeSeparator),
      'response_type' => 'code',
      'response_mode' => 'form_post',
    ];

    if ($this->usesState()) {
      $fields['state'] = $state;
    }

    return array_merge($fields, $this->parameters);
  }

  private function isISSInvalid(string $iss): bool
  {
    return $iss !== self::URL;
  }

  private function isTokenExpired(string $timestamp): bool
  {
    return Carbon::createFromTimestamp($timestamp)->isPast();
  }

  private function isAudienceInvalid(string $audience)
  {
    return $this->clientId === $audience;
  }

  protected function getClaims(string $token)
  {
    $payload = explode('.', $token)[1];

    return json_decode($payload, true);
  }

  protected function getUserByToken($token)
  {
    $claims = $this->getClaims($token);

    if ($this->isISSInvalid($claims['iss'])) {
      throw new InvalidTokenException("The registered issuer doesn't match with apple issuer", Response::HTTP_UNAUTHORIZED);
    }

    if ($this->isAudienceInvalid($claims['aud'])) {
      throw new InvalidTokenException("Invalid client.", Response::HTTP_UNAUTHORIZED);
    }

    if ($this->isTokenExpired($claims['exp'])) {
      throw new InvalidTokenException("Token expired.", Response::HTTP_UNAUTHORIZED);
    }

    return $claims;
  }

  protected function mapUserToObject(array $user)
  {
    return (new User)->setRaw($user)->map([
      'id' => $user['sub'],
      'email' => $user['email'],
      'name' => $this->request->get('additional_data')['name'] ?? ''
    ]);
  }
}
