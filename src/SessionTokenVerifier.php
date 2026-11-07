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
        $claims = json_decode((string) base64_decode($payload.str_repeat('=', (4 - strlen($payload) % 4) % 4)), true);

        return is_array($claims)
            && ($claims['v'] ?? null) === '2'
            && isset($claims['sid'], $claims['fva']);
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
            // cached; look once more before refusing the token.
            if ($kid !== null && ! array_key_exists($kid, $keys)) {
                $this->forgetKeys();
                $keys = $this->verificationKeys();

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
        $decoded = json_decode((string) base64_decode($header.str_repeat('=', (4 - strlen($header) % 4) % 4)), true);

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
                $response = Http::connectTimeout(3)->timeout(10)->acceptJson()
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

            return JWK::parseKeySet(is_array($document) ? $document : []);
        } catch (InvalidSessionToken $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new InvalidSessionToken('Unable to load the verification keys: '.$exception->getMessage(), 0, $exception);
        }
    }

    protected function cacheKey(): string
    {
        return 'koamishin.jwks.'.sha1($this->portalUrl);
    }

    protected function forgetKeys(): void
    {
        Cache::forget($this->cacheKey());
    }
}
