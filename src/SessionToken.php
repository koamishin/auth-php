<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use InvalidArgumentException;

/**
 * A short-lived session token minted by Koamishin Auth.
 *
 * The claims on the token are only trustworthy once {@see SessionTokenVerifier}
 * has verified the signature; treat {@see self::unverifiedClaims()} as a
 * convenience for logging and debugging, never for authorization.
 */
class SessionToken
{
    public function __construct(
        public readonly string $token,
        public readonly string $tokenType,
        public readonly int $expiresIn,
        public readonly int $expiresAt,
    ) {}

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $expiresIn = $data['expires_in'] ?? null;
        $expiresAt = $data['expires_at'] ?? null;

        if (! is_string($data['token'] ?? null) || $data['token'] === ''
            || ! is_string($data['token_type'] ?? null) || $data['token_type'] === ''
            || ! is_numeric($expiresIn) || (int) $expiresIn <= 0
            || ! is_numeric($expiresAt) || (int) $expiresAt <= 0) {
            throw new InvalidArgumentException('Koamishin returned an invalid session token response.');
        }

        return new self(
            token: $data['token'],
            tokenType: $data['token_type'],
            expiresIn: (int) $expiresIn,
            expiresAt: (int) $expiresAt,
        );
    }

    /**
     * The token's claims, decoded without verifying the signature.
     *
     * @return array<string, mixed>
     */
    public function unverifiedClaims(): array
    {
        $parts = explode('.', $this->token);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('The session token is not a JWT.');
        }

        $payload = strtr($parts[1], '-_', '+/');
        $claims = json_decode((string) base64_decode($payload.str_repeat('=', (4 - strlen($payload) % 4) % 4), true), true);
        if (! is_array($claims)) {
            throw new InvalidArgumentException('The session token payload is not valid JSON.');
        }

        return $claims;
    }

    public function isExpired(): bool
    {
        return $this->expiresAt <= time();
    }
}
