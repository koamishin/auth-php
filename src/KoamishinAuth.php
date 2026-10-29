<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;
use InvalidArgumentException;
use RuntimeException;

class KoamishinAuth
{
    /**
     * @param  list<string>  $scopes
     */
    public function __construct(
        protected string $portalUrl,
        protected string $clientId,
        protected string $clientSecret,
        protected string $redirectUri,
        protected array $scopes = ['openid', 'profile', 'email', 'roles', 'metadata:public'],
        protected string $applicationId = '',
        protected string $environment = '',
    ) {
        $this->portalUrl = rtrim($portalUrl, '/');
    }

    public function getLoginUrl(?string $returnTo = null): string
    {
        $this->validateApplicationContext();

        $state = bin2hex(random_bytes(16));
        $codeVerifier = bin2hex(random_bytes(32));
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
        $transactions = Session::get('koamishin_oauth_transactions', []);
        $transactions = is_array($transactions) ? $transactions : [];
        $transactions = array_filter($transactions, fn ($transaction): bool => is_array($transaction) && (int) ($transaction['created_at'] ?? 0) >= time() - 600);
        $transactions = array_slice($transactions, -9, null, true);
        $transactions[$state] = [
            'verifier' => $codeVerifier,
            'return_to' => self::safeReturnTo($returnTo),
            'created_at' => time(),
        ];
        Session::put('koamishin_oauth_transactions', $transactions);

        $query = http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $this->scopes),
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ]);

        return "{$this->portalUrl}/oauth/authorize?{$query}";
    }

    public function getRegistrationUrl(?string $returnTo = null): string
    {
        return $this->getLoginUrl($returnTo).'&screen_hint=signup';
    }

    public function handleCallback(string $code, string $state): KoamishinUser
    {
        $transactions = Session::get('koamishin_oauth_transactions', []);
        $transaction = is_array($transactions) ? ($transactions[$state] ?? null) : null;

        if (! preg_match('/\A[a-f0-9]{32}\z/', $state) || ! is_array($transaction) || (int) ($transaction['created_at'] ?? 0) < time() - 600 || ! is_string($transaction['verifier'] ?? null) || $code === '') {
            throw new InvalidArgumentException('Invalid or expired OAuth transaction.');
        }

        unset($transactions[$state]);
        Session::put('koamishin_oauth_transactions', $transactions);

        $response = Http::connectTimeout(3)->timeout(10)->asForm()->post("{$this->portalUrl}/oauth/token", [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $transaction['verifier'],
            'code' => $code,
        ]);

        $tokens = $this->validatedTokens($response);
        $user = $this->userForToken($tokens['access_token']);
        if ($user === null) {
            throw new RuntimeException('Portal rejected the new access token.');
        }

        Session::regenerate(true);
        $this->storeTokens($tokens);
        Session::put('koamishin_user_id', $user->id);
        Session::put('koamishin_return_to', $transaction['return_to'] ?? null);

        return $user;
    }

    /**
     * Revalidate the stored access token and current claims against the Portal.
     */
    public function user(): ?KoamishinUser
    {
        $accessToken = $this->decryptSessionToken('koamishin_access_token');
        $expiresAt = Session::get('koamishin_token_expires_at');
        $userId = Session::get('koamishin_user_id');
        if ($accessToken === null || ! is_numeric($expiresAt) || ! is_string($userId) || $userId === '') {
            $this->clearSession();

            return null;
        }

        if ((int) $expiresAt <= time()) {
            if (! $this->refresh()) {
                return null;
            }
            $accessToken = $this->decryptSessionToken('koamishin_access_token');
            if ($accessToken === null) {
                $this->clearSession();

                return null;
            }
        }

        $user = $this->userForToken($accessToken);
        if ($user === null || ! hash_equals($userId, $user->id)) {
            $this->clearSession();

            return null;
        }

        return $user;
    }

    /**
     * Authenticate a bearer token without saving it in the session.
     */
    public function userForToken(string $accessToken): ?KoamishinUser
    {
        if ($accessToken === '') {
            return null;
        }

        $this->validateApplicationContext();

        $response = Http::connectTimeout(3)->timeout(10)->withToken($accessToken)
            ->acceptJson()->get("{$this->portalUrl}/api/oauth/userinfo");
        if ($response->status() === 401 || $response->status() === 403) {
            return null;
        }
        if (! $response->successful()) {
            throw new RuntimeException('Unable to fetch userinfo from the Portal.');
        }

        $data = $response->json();
        if (! is_array($data) || ! is_string($data['sub'] ?? null) || $data['sub'] === '' || ! is_string($data['application_id'] ?? null) || ! is_string($data['environment'] ?? null)) {
            throw new RuntimeException('Portal returned invalid userinfo.');
        }

        if (! hash_equals($this->applicationId, $data['application_id']) || ! hash_equals($this->environment, $data['environment'])) {
            return null;
        }

        return KoamishinUser::fromArray($data);
    }

    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Remove this application's Koamishin session; this does not revoke Portal tokens.
     */
    public function logout(): void
    {
        $this->clearSession();
        Session::forget(['koamishin_oauth_transactions', 'koamishin_return_to']);
        Session::regenerate(true);
    }

    public function consumeReturnTo(string $default = '/'): string
    {
        return self::safeReturnTo(Session::pull('koamishin_return_to')) ?? self::safeReturnTo($default) ?? '/';
    }

    protected function refresh(): bool
    {
        $refreshToken = $this->decryptSessionToken('koamishin_refresh_token');
        if ($refreshToken === null) {
            $this->clearSession();

            return false;
        }

        $response = Http::connectTimeout(3)->timeout(10)->asForm()->post("{$this->portalUrl}/oauth/token", [
            'grant_type' => 'refresh_token',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'refresh_token' => $refreshToken,
        ]);
        if ($response->status() >= 400 && $response->status() < 500) {
            $this->clearSession();

            return false;
        }

        $this->storeTokens($this->validatedTokens($response));

        return true;
    }

    /**
     * @return array{access_token: string, refresh_token: ?string, expires_in: int}
     */
    protected function validatedTokens(Response $response): array
    {
        if (! $response->successful()) {
            throw new RuntimeException('OAuth token exchange failed.');
        }
        $data = $response->json();
        $expiresIn = is_array($data) ? ($data['expires_in'] ?? null) : null;
        if (! is_array($data) || ! is_string($data['access_token'] ?? null) || $data['access_token'] === '' || ! is_numeric($expiresIn) || (int) $expiresIn <= 0 || (int) $expiresIn > PHP_INT_MAX - time()) {
            throw new RuntimeException('Portal returned an invalid token response.');
        }

        return [
            'access_token' => $data['access_token'],
            'refresh_token' => is_string($data['refresh_token'] ?? null) && $data['refresh_token'] !== '' ? $data['refresh_token'] : null,
            'expires_in' => (int) $expiresIn,
        ];
    }

    /**
     * @param  array{access_token: string, refresh_token: ?string, expires_in: int}  $tokens
     */
    protected function storeTokens(array $tokens): void
    {
        Session::put('koamishin_access_token', Crypt::encryptString($tokens['access_token']));
        Session::put('koamishin_token_expires_at', time() + $tokens['expires_in']);
        if ($tokens['refresh_token'] !== null) {
            Session::put('koamishin_refresh_token', Crypt::encryptString($tokens['refresh_token']));
        } else {
            Session::forget('koamishin_refresh_token');
        }
    }

    protected function decryptSessionToken(string $key): ?string
    {
        $value = Session::get($key);
        if (! is_string($value) || $value === '') {
            return null;
        }

        try {
            $token = Crypt::decryptString($value);

            return $token !== '' ? $token : null;
        } catch (DecryptException) {
            return null;
        }
    }

    protected function clearSession(): void
    {
        Session::forget(['koamishin_user', 'koamishin_user_id', 'koamishin_access_token', 'koamishin_refresh_token', 'koamishin_token_expires_at']);
    }

    protected function validateApplicationContext(): void
    {
        if (trim($this->applicationId) === '' || ! in_array($this->environment, ['development', 'production'], true)) {
            throw new RuntimeException('Koamishin application ID and environment must be configured.');
        }
    }

    protected static function safeReturnTo(mixed $url): ?string
    {
        if (! is_string($url) || $url === '' || ! str_starts_with($url, '/') || str_starts_with($url, '//') || preg_match('/[\x00-\x20\x7f\\\\]/', rawurldecode($url))) {
            return null;
        }

        $decoded = rawurldecode($url);
        if (str_starts_with($decoded, '//') || parse_url($url, PHP_URL_HOST) !== null) {
            return null;
        }

        return $url;
    }
}
