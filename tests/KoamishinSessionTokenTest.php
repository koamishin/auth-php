<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;
use Koamishin\Auth\InvalidSessionToken;
use Koamishin\Auth\KoamishinAuth;
use Koamishin\Auth\KoamishinServiceProvider;
use Koamishin\Auth\Middleware\AuthenticateWithKoamishin;
use Koamishin\Auth\SessionTokenVerifier;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

require_once __DIR__.'/Support/bootstrap.php';

class KoamishinSessionTokenTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->app->register(KoamishinServiceProvider::class);
        config([
            'koamishin.portal_url' => 'https://portal.test',
            'koamishin.client_id' => 'client-id',
            'koamishin.client_secret' => 'client-secret',
            'koamishin.redirect_uri' => 'https://client.test/callback',
            'koamishin.application_id' => '100',
            'koamishin.environment' => 'production',
            'auth.guards.koamishin' => ['driver' => 'koamishin'],
        ]);
        Session::start();
        Http::preventStrayRequests();
    }

    public function test_session_token_mints_from_the_current_session(): void
    {
        $this->signedInSession();
        [$privatePem] = $this->keyPair();
        $minted = $this->sign($this->claims(), $privatePem);
        Http::fake([
            'https://portal.test/api/oauth/session-token' => Http::response([
                'token' => $minted,
                'token_type' => 'Bearer',
                'expires_in' => 60,
                'expires_at' => time() + 60,
            ]),
        ]);

        $token = app(KoamishinAuth::class)->sessionToken();

        $this->assertSame($minted, $token->token);
        $this->assertSame('Bearer', $token->tokenType);
        $this->assertSame(60, $token->expiresIn);
        $this->assertFalse($token->isExpired());
        $this->assertSame('user-1', $token->unverifiedClaims()['sub']);
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/api/oauth/session-token'
            && $request->hasHeader('Authorization', 'Bearer access-secret'));
    }

    public function test_session_token_requires_an_active_session(): void
    {
        $this->expectException(RuntimeException::class);

        app(KoamishinAuth::class)->sessionToken();
    }

    public function test_session_token_refreshes_an_expired_access_token_first(): void
    {
        Session::put('koamishin_access_token', Crypt::encryptString('stale-secret'));
        Session::put('koamishin_refresh_token', Crypt::encryptString('refresh-secret'));
        Session::put('koamishin_token_expires_at', time() - 10);
        Session::put('koamishin_user_id', 'user-1');
        Http::fake([
            'https://portal.test/oauth/token' => Http::response([
                'access_token' => 'fresh-secret', 'refresh_token' => 'refresh-secret', 'expires_in' => 600,
            ]),
            'https://portal.test/api/oauth/session-token' => Http::response([
                'token' => 'header.payload.sig', 'token_type' => 'Bearer', 'expires_in' => 60, 'expires_at' => time() + 60,
            ]),
        ]);

        app(KoamishinAuth::class)->sessionToken();

        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/api/oauth/session-token'
            && $request->hasHeader('Authorization', 'Bearer fresh-secret'));
    }

    public function test_verifier_validates_a_signed_session_token(): void
    {
        [$privatePem, $jwk] = $this->keyPair();
        Http::fake(['https://portal.test/oauth/jwks' => Http::response(['keys' => [$jwk]])]);
        $jwt = $this->sign($this->claims(), $privatePem);

        $claims = (new SessionTokenVerifier('https://portal.test'))->verify($jwt);

        $this->assertSame('user-1', $claims['sub']);
        $this->assertSame('https://portal.test', $claims['iss']);
        $this->assertSame('100', $claims['application_id']);
        $this->assertSame('production', $claims['environment']);
    }

    public function test_verifier_refuses_an_expired_token(): void
    {
        [$privatePem, $jwk] = $this->keyPair();
        Http::fake(['https://portal.test/oauth/jwks' => Http::response(['keys' => [$jwk]])]);
        $jwt = $this->sign($this->claims(['iat' => time() - 120, 'nbf' => time() - 120, 'exp' => time() - 60]), $privatePem);

        $this->expectException(InvalidSessionToken::class);

        (new SessionTokenVerifier('https://portal.test'))->verify($jwt);
    }

    public function test_verifier_refuses_a_foreign_issuer(): void
    {
        [$privatePem, $jwk] = $this->keyPair();
        Http::fake(['https://portal.test/oauth/jwks' => Http::response(['keys' => [$jwk]])]);
        $jwt = $this->sign($this->claims(['iss' => 'https://attacker.test']), $privatePem);

        $this->expectException(InvalidSessionToken::class);

        (new SessionTokenVerifier('https://portal.test'))->verify($jwt);
    }

    public function test_verifier_refuses_a_signature_that_does_not_match_the_published_key(): void
    {
        [, $jwk] = $this->keyPair();
        [$foreignPem] = $this->keyPair('b');
        Http::fake(['https://portal.test/oauth/jwks' => Http::response(['keys' => [$jwk]])]);

        // A token signed by another key that claims to be the published one.
        $jwt = $this->sign($this->claims(), $foreignPem, 'key-a');

        $this->expectException(InvalidSessionToken::class);

        (new SessionTokenVerifier('https://portal.test'))->verify($jwt);
    }

    public function test_verifier_refreshes_the_key_set_once_for_an_unknown_key(): void
    {
        [, $oldJwk] = $this->keyPair();
        [$newPem, $newJwk] = $this->keyPair('b');
        Http::fake(['https://portal.test/oauth/jwks' => Http::sequence()
            ->push(['keys' => [$oldJwk]])
            ->push(['keys' => [$newJwk]])]);
        $jwt = $this->sign($this->claims(), $newPem, 'key-b');

        $claims = (new SessionTokenVerifier('https://portal.test'))->verify($jwt);

        $this->assertSame('user-1', $claims['sub']);
        Http::assertSentCount(2);
    }

    public function test_verifier_refuses_a_key_it_knows_nothing_about(): void
    {
        [, $jwk] = $this->keyPair();
        [$unknownPem] = $this->keyPair('b');
        Http::fake(['https://portal.test/oauth/jwks' => Http::sequence()
            ->push(['keys' => [$jwk]])
            ->push(['keys' => [$jwk]])]);
        $jwt = $this->sign($this->claims(), $unknownPem, 'key-b');

        $this->expectException(InvalidSessionToken::class);

        (new SessionTokenVerifier('https://portal.test'))->verify($jwt);
    }

    public function test_user_for_session_token_binds_to_the_application(): void
    {
        [$privatePem, $jwk] = $this->keyPair();
        Http::fake(['https://portal.test/oauth/jwks' => Http::response(['keys' => [$jwk]])]);
        $auth = app(KoamishinAuth::class);

        $user = $auth->userForSessionToken($this->sign($this->claims(), $privatePem));

        $this->assertNotNull($user);
        $this->assertSame('user-1', $user->id);
        $this->assertSame('100', $user->applicationId);
        $this->assertSame('production', $user->environment);
        $this->assertSame('7', $user->organizationId);
        $this->assertSame(['admin'], $user->roles);
        $this->assertTrue($user->hasRole('admin'));

        // A token for another application, and a plain access token JWT with no
        // application context, are both refused.
        $this->assertNull($auth->userForSessionToken($this->sign($this->claims(['application_id' => '200']), $privatePem)));
        $this->assertNull($auth->userForSessionToken($this->sign([
            'sub' => 'user-1', 'iss' => 'https://portal.test', 'iat' => time(), 'exp' => time() + 60,
        ], $privatePem)));
    }

    public function test_middleware_authenticates_bearer_session_tokens_offline(): void
    {
        [$privatePem, $jwk] = $this->keyPair();
        Http::fake(['https://portal.test/oauth/jwks' => Http::response(['keys' => [$jwk]])]);
        $jwt = $this->sign($this->claims(), $privatePem);
        $request = Request::create('/private', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$jwt]);

        $response = app(AuthenticateWithKoamishin::class)->handle(
            $request,
            fn (Request $request): Response => response($request->user()->id),
            'admin',
        );

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('user-1', $response->getContent());
        // The only call made was the key fetch; userinfo was never touched.
        Http::assertSentCount(1);
    }

    public function test_middleware_refuses_session_tokens_for_another_application(): void
    {
        [$privatePem, $jwk] = $this->keyPair();
        Http::fake(['https://portal.test/oauth/jwks' => Http::response(['keys' => [$jwk]])]);
        $jwt = $this->sign($this->claims(['application_id' => '200']), $privatePem);
        $request = Request::create('/private', 'GET', server: [
            'HTTP_AUTHORIZATION' => 'Bearer '.$jwt,
            'HTTP_ACCEPT' => 'application/json',
        ]);

        $response = app(AuthenticateWithKoamishin::class)->handle(
            $request,
            fn (): Response => response('unexpected'),
        );

        $this->assertSame(401, $response->getStatusCode());
    }

    public function test_is_session_token_distinguishes_session_tokens(): void
    {
        [$privatePem] = $this->keyPair();

        $this->assertTrue(SessionTokenVerifier::isSessionToken($this->sign($this->claims(), $privatePem)));
        $this->assertFalse(SessionTokenVerifier::isSessionToken('not-a-jwt'));
        $this->assertFalse(SessionTokenVerifier::isSessionToken($this->sign([
            'sub' => 'user-1', 'iss' => 'https://portal.test', 'iat' => time(), 'exp' => time() + 60,
        ], $privatePem)));
    }

    /**
     * A fixed test key pair and the JWKS entry for its public half.
     *
     * @return array{0: string, 1: array<string, string>}
     */
    private function keyPair(string $pair = 'a'): array
    {
        $privatePem = (string) file_get_contents(__DIR__.'/Support/test-key-'.$pair.'.pem');
        /** @var array<string, string> $jwk */
        $jwk = json_decode((string) file_get_contents(__DIR__.'/Support/test-key-'.$pair.'.json'), true);

        return [$privatePem, $jwk + ['kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => 'key-'.$pair]];
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function sign(array $claims, string $privatePem, string $kid = 'key-a'): string
    {
        return JWT::encode($claims, $privatePem, 'RS256', $kid);
    }

    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    private function claims(array $overrides = []): array
    {
        return array_replace([
            'sub' => 'user-1',
            'iss' => 'https://portal.test',
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + 60,
            'jti' => 'token-1',
            'sid' => 'session-1',
            'v' => '2',
            'fva' => [0, -1],
            'sts' => 'active',
            'tasks' => [],
            'application_id' => '100',
            'environment' => 'production',
            'o' => ['id' => '7', 'slg' => 'acme', 'rol' => 'admin'],
        ], $overrides);
    }

    private function signedInSession(): void
    {
        Session::put('koamishin_access_token', Crypt::encryptString('access-secret'));
        Session::put('koamishin_refresh_token', Crypt::encryptString('refresh-secret'));
        Session::put('koamishin_token_expires_at', time() + 300);
        Session::put('koamishin_user_id', 'user-1');
    }
}
