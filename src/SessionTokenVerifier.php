<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Verifies Koamishin session tokens offline.
 *
 * A session token is an RS256 JWT signed with the key pair behind the
 * Koamishin Auth JWKS document. Verification needs no call back to Koamishin
 * Auth per request: the key set is fetched once and cached, and every token is
 * checked against it. Tokens are minted for one application, so a backend
 * should also check the `application_id` and `environment` claims against its
 * own configuration before trusting one — {@see KoamishinAuth::userForSessionToken()}
 * does exactly that.
 */
class SessionTokenVerifier
{
    /**
     * @param  string  $issuer  The expected `iss` claim; the portal URL by default.
     * @param  int  $leewaySeconds  Clock skew tolerated around `exp` and `nbf`.
     * @param  int  $jwksCacheSeconds  How long the fetched key set is cached.
     */
    public function __construct(
        protected string $portalUrl,
        protected string $issuer = '',
        protected int $leewaySeconds = 10,
        protected int $jwksCacheSeconds = 3600,
    ) {
        $this->portalUrl = rtrim($portalUrl, '/');
        $this->issuer = $issuer !== '' ? $issuer : $this->portalUrl;
    }

    /**
     * Whether a token has the shape of a session token.
     *
     * This is a routing hint only — the unverified payload is never trusted;
     * verify the token before using any claim on it.
     */
    public static function isSessionToken(string $token): bool
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return false;
        }

        $payload = strtr($parts[1], '-_', '+/');
        $decoded = base64_decode($payload.str_repeat('=', (4 - strlen($payload) % 4) % 4), true);
        if (! is_string($decoded)) {
            return false;
        }

        $claims = json_decode($decoded, true);

        return is_array($claims)
            && ($claims['v'] ?? null) === '2'
            && is_string($claims['sid'] ?? null)
            && $claims['sid'] !== ''
            && isset($claims['fva']);
    }

    /**
     * Verify a session token and return its claims.
     *
     * @return array<string, mixed>
     *
     * @throws InvalidSessionToken
     */
    public function verify(string $token): array
    {
        try {
            $keys = $this->verificationKeys();
            $kid = $this->peekKid($token);

            // A kid we do not know may mean the key set rotated since it was
            // cached; look once more (throttled per portal) before refusing.
            if ($kid !== null && ! array_key_exists($kid, $keys)) {
                if (Cache::add($this->refreshCooldownKey(), true, 30)) {
                    $this->forgetKeys();
                    $keys = $this->verificationKeys();
                }

                if (! array_key_exists($kid, $keys)) {
                    throw new InvalidSessionToken('The session token was signed with an unknown key.');
                }
            }

            $previousLeeway = JWT::$leeway;
            JWT::$leeway = $this->leewaySeconds;

            try {
                $decoded = JWT::decode($token, $keys);
            } finally {
                JWT::$leeway = $previousLeeway;
            }
        } catch (InvalidSessionToken $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new InvalidSessionToken('The session token is not valid: '.$exception->getMessage(), 0, $exception);
        }

        /** @var array<string, mixed> $claims */
        $claims = json_decode((string) json_encode($decoded), true) ?? [];

        if (! is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            throw new InvalidSessionToken('The session token has no subject.');
        }

        if (! is_string($claims['iss'] ?? null) || ! hash_equals($this->issuer, $claims['iss'])) {
            throw new InvalidSessionToken('The session token was issued by someone else.');
        }

        if (! is_numeric($claims['exp'] ?? null)) {
            throw new InvalidSessionToken('The session token has no expiration.');
        }

        if (isset($claims['iat']) && is_numeric($claims['iat']) && (int) $claims['iat'] > time() + $this->leewaySeconds) {
            throw new InvalidSessionToken('The session token was issued in the future.');
        }

        if (($claims['v'] ?? null) !== '2' || ! is_string($claims['sid'] ?? null) || $claims['sid'] === '') {
            throw new InvalidSessionToken('The session token is missing required session claims.');
        }

        return $claims;
    }

    /**
     * The kid in the token header, read only to pick a key; the signature is
     * what makes a claim trustworthy.
     */
    protected function peekKid(string $token): ?string
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidSessionToken('The session token is not a JWT.');
        }

        $header = strtr($parts[0], '-_', '+/');
        $rawHeader = base64_decode($header.str_repeat('=', (4 - strlen($header) % 4) % 4), true);
        if (! is_string($rawHeader)) {
            throw new InvalidSessionToken('The session token header is not valid base64.');
        }

        $decoded = json_decode($rawHeader, true);

        if (! is_array($decoded) || ($decoded['alg'] ?? null) !== 'RS256') {
            throw new InvalidSessionToken('The session token is not an RS256 JWT.');
        }

        return is_string($decoded['kid'] ?? null) && $decoded['kid'] !== '' ? $decoded['kid'] : null;
    }

    /**
     * The cached verification keys, keyed by kid.
     *
     * @return array<string, Key>
     */
    protected function verificationKeys(): array
    {
        try {
            /** @var mixed $document */
            $document = Cache::remember($this->cacheKey(), $this->jwksCacheSeconds, function (): array {
                $response = Http::connectTimeout(3)->timeout(10)->withoutRedirecting()->acceptJson()
                    ->get("{$this->portalUrl}/oauth/jwks");

                if (! $response->successful()) {
                    throw new InvalidSessionToken('Koamishin Auth did not return its verification keys.');
                }

                $document = $response->json();
                if (! is_array($document) || ! is_array($document['keys'] ?? null) || $document['keys'] === []) {
                    throw new InvalidSessionToken('Koamishin Auth returned no verification keys.');
                }

                return $document;
            });

            $keys = is_array($document['keys'] ?? null) ? array_values(array_filter(
                $document['keys'],
                fn (mixed $jwk): bool => $this->isSupportedSigningJwk($jwk),
            )) : [];

            if ($keys === []) {
                throw new InvalidSessionToken('Koamishin Auth returned no usable verification keys.');
            }

            return JWK::parseKeySet(['keys' => $keys]);
        } catch (InvalidSessionToken $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new InvalidSessionToken('Unable to load the verification keys: '.$exception->getMessage(), 0, $exception);
        }
    }

    protected function isSupportedSigningJwk(mixed $jwk): bool
    {
        if (! is_array($jwk) || ($jwk['kty'] ?? null) !== 'RSA') {
            return false;
        }

        if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
            return false;
        }

        if (isset($jwk['alg']) && $jwk['alg'] !== 'RS256') {
            return false;
        }

        if (! is_string($jwk['n'] ?? null) || $jwk['n'] === '') {
            return false;
        }

        $padded = strtr($jwk['n'], '-_', '+/');
        $modulus = base64_decode($padded.str_repeat('=', (4 - strlen($padded) % 4) % 4), true);

        return is_string($modulus) && strlen($modulus) >= 256;
    }

    protected function cacheKey(): string
    {
        return 'koamishin.jwks.'.sha1($this->portalUrl);
    }

    protected function refreshCooldownKey(): string
    {
        return 'koamishin.jwks.cooldown.'.sha1($this->portalUrl);
    }

    protected function forgetKeys(): void
    {
        Cache::forget($this->cacheKey());
    }
}
