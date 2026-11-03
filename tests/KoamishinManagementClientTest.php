<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Koamishin\Auth\KoamishinManagementClient;
use Koamishin\Auth\KoamishinServiceProvider;
use Tests\TestCase;

require_once __DIR__.'/Support/bootstrap.php';

class KoamishinManagementClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->app->register(KoamishinServiceProvider::class);
        config([
            'koamishin.portal_url' => 'https://portal.test',
            'koamishin.management_client_id' => 'management-id',
            'koamishin.management_client_secret' => 'management-secret',
        ]);
        Http::preventStrayRequests();
    }

    public function test_lists_users_with_a_scoped_machine_token(): void
    {
        Http::fake([
            'https://portal.test/oauth/token' => Http::response(['access_token' => 'machine-token']),
            'https://portal.test/api/v1/users*' => Http::response(['data' => [['id' => 42, 'name' => 'Example', 'email' => 'user@example.test']], 'links' => [], 'meta' => ['current_page' => 1]]),
        ]);

        $result = app(KoamishinManagementClient::class)->listUsers();

        $this->assertSame('42', $result['data'][0]->id);
        $this->assertSame(1, $result['meta']['current_page']);
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/oauth/token' && $request['grant_type'] === 'client_credentials' && $request['client_id'] === 'management-id' && $request['scope'] === 'users:read');
        Http::assertSent(fn ($request): bool => str_starts_with($request->url(), 'https://portal.test/api/v1/users') && $request->hasHeader('Authorization', 'Bearer machine-token'));
    }

    public function test_reads_the_organization_bound_to_the_management_client(): void
    {
        Http::fake([
            'https://portal.test/oauth/token' => Http::response(['access_token' => 'machine-token']),
            'https://portal.test/api/v1/organization' => Http::response(['data' => [
                'id' => '10',
                'name' => 'Example',
                'slug' => 'example',
                'application_id' => '100',
                'environment' => 'production',
            ]]),
        ]);

        $organization = app(KoamishinManagementClient::class)->getOrganization();

        $this->assertSame('10', $organization['id']);
        $this->assertSame('production', $organization['environment']);
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/oauth/token' && $request['scope'] === 'organization:read');
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/api/v1/organization' && $request->hasHeader('Authorization', 'Bearer machine-token'));
    }

    public function test_replaces_only_the_provided_metadata_bucket(): void
    {
        Http::fake([
            'https://portal.test/oauth/token' => Http::response(['access_token' => 'machine-token']),
            'https://portal.test/api/v1/users/42/metadata' => Http::response(['data' => ['public' => [], 'private' => ['internal' => 'kept']]]),
        ]);

        $result = app(KoamishinManagementClient::class)->updateUserMetadata('42', public: []);

        $this->assertSame(['public' => [], 'private' => ['internal' => 'kept']], $result);
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/oauth/token' && $request['scope'] === 'metadata:read metadata:write');
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/api/v1/users/42/metadata' && $request->method() === 'PATCH' && $request->body() === '{"public":{}}');
    }

    public function test_lists_application_grants_with_the_sessions_read_scope(): void
    {
        Http::fake([
            'https://portal.test/oauth/token' => Http::response(['access_token' => 'machine-token']),
            'https://portal.test/api/v1/users/42/sessions*' => Http::response([
                'data' => [['id' => 'grant-1', 'access_revoked' => false]],
                'links' => [],
                'meta' => ['current_page' => 2],
            ]),
        ]);

        $result = app(KoamishinManagementClient::class)->listUserSessions('42', page: 2, perPage: 25);

        $this->assertSame('grant-1', $result['data'][0]['id']);
        $this->assertSame(2, $result['meta']['current_page']);
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/oauth/token' && $request['scope'] === 'sessions:read');
        Http::assertSent(fn ($request): bool => str_starts_with($request->url(), 'https://portal.test/api/v1/users/42/sessions') && $request['page'] === 2 && $request['per_page'] === 25 && $request->hasHeader('Authorization', 'Bearer machine-token'));
    }

    public function test_enrolls_an_existing_organization_member_in_the_application(): void
    {
        Http::fake([
            'https://portal.test/oauth/token' => Http::response(['access_token' => 'machine-token']),
            'https://portal.test/api/v1/users/42/membership' => Http::response('', 204),
        ]);

        app(KoamishinManagementClient::class)->enrollUserInApplication('42');

        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/oauth/token' && $request['scope'] === 'memberships:write');
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/api/v1/users/42/membership' && $request->method() === 'PUT' && $request->body() === '' && $request->hasHeader('Authorization', 'Bearer machine-token'));
    }

    public function test_removes_an_application_membership_with_the_memberships_write_scope(): void
    {
        Http::fake([
            'https://portal.test/oauth/token' => Http::response(['access_token' => 'machine-token']),
            'https://portal.test/api/v1/users/42/membership' => Http::response('', 204),
        ]);

        app(KoamishinManagementClient::class)->removeUserFromApplication('42');

        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/oauth/token' && $request['scope'] === 'memberships:write');
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/api/v1/users/42/membership' && $request->method() === 'DELETE' && $request->hasHeader('Authorization', 'Bearer machine-token'));
    }

    public function test_revokes_a_grant_with_a_separate_scope_and_accepts_a_204_response(): void
    {
        Http::fake([
            'https://portal.test/oauth/token' => Http::response(['access_token' => 'machine-token']),
            'https://portal.test/api/v1/users/42/sessions/grant-1' => Http::response('', 204),
        ]);

        app(KoamishinManagementClient::class)->revokeUserSession('42', 'grant-1');

        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/oauth/token' && $request['scope'] === 'sessions:revoke');
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/api/v1/users/42/sessions/grant-1' && $request->method() === 'DELETE' && $request->hasHeader('Authorization', 'Bearer machine-token'));
    }

    public function test_failed_management_request_does_not_expose_response_body(): void
    {
        Http::fake([
            'https://portal.test/oauth/token' => Http::response(['access_token' => 'machine-token']),
            'https://portal.test/api/v1/users/42' => Http::response(['secret' => 'do-not-log'], 403),
        ]);

        try {
            app(KoamishinManagementClient::class)->getUser('42');
            $this->fail('The forbidden request was accepted.');
        } catch (RuntimeException $exception) {
            $this->assertSame('Management API request failed with status 403.', $exception->getMessage());
        }
    }

    public function test_missing_machine_credentials_fail_before_sending_a_request(): void
    {
        Http::fake(['https://portal.test/*' => Http::response()]);

        try {
            (new KoamishinManagementClient('https://portal.test', '', ''))->listUsers();
            $this->fail('Missing credentials were accepted.');
        } catch (RuntimeException $exception) {
            $this->assertSame('Management API credentials are not configured.', $exception->getMessage());
            Http::assertNothingSent();
        }
    }

    public function test_authenticates_management_requests_directly_with_a_secret_key(): void
    {
        config([
            'koamishin.management_client_id' => '',
            'koamishin.management_client_secret' => '',
            'koamishin.secret_key' => 'sk_live_backend_123',
        ]);
        Http::fake([
            'https://portal.test/api/v1/users/42/metadata' => Http::response(['data' => ['public' => ['plan' => 'pro'], 'private' => []]]),
            'https://portal.test/api/v1/users*' => Http::response(['data' => [['id' => 42, 'name' => 'Example', 'email' => 'user@example.test']], 'links' => [], 'meta' => ['current_page' => 1]]),
            'https://portal.test/api/v1/organization' => Http::sequence()
                ->push(['data' => ['id' => '10', 'name' => 'Example', 'slug' => 'example', 'application_id' => '100', 'environment' => 'production']])
                ->push(['data' => ['id' => '10', 'name' => 'Example', 'slug' => 'example', 'application_id' => '100', 'environment' => 'development']]),
        ]);

        $client = app(KoamishinManagementClient::class);
        $users = $client->listUsers();
        $organization = $client->getOrganization();
        $metadata = $client->updateUserMetadata('42', public: ['plan' => 'pro']);
        $testOrganization = (new KoamishinManagementClient('https://portal.test', secretKey: 'sk_test_backend_456'))->getOrganization();

        $this->assertSame('42', $users['data'][0]->id);
        $this->assertSame('production', $organization['environment']);
        $this->assertSame(['public' => ['plan' => 'pro'], 'private' => []], $metadata);
        $this->assertSame('development', $testOrganization['environment']);
        Http::assertNotSent(fn ($request): bool => $request->url() === 'https://portal.test/oauth/token');
        Http::assertSent(fn ($request): bool => str_starts_with($request->url(), 'https://portal.test/api/v1/users?') && $request->hasHeader('Authorization', 'Bearer sk_live_backend_123'));
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/api/v1/users/42/metadata' && $request->method() === 'PATCH' && $request->hasHeader('Authorization', 'Bearer sk_live_backend_123'));
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/api/v1/organization' && $request->hasHeader('Authorization', 'Bearer sk_test_backend_456'));
    }

    public function test_prefers_explicit_management_client_credentials_when_secret_key_is_also_configured(): void
    {
        config([
            'koamishin.management_client_id' => 'management-id',
            'koamishin.management_client_secret' => 'management-secret',
            'koamishin.secret_key' => 'sk_live_backend_123',
        ]);
        Http::fake([
            'https://portal.test/oauth/token' => Http::response(['access_token' => 'machine-token']),
            'https://portal.test/api/v1/organization' => Http::response(['data' => [
                'id' => '10',
                'name' => 'Example',
                'slug' => 'example',
                'application_id' => '100',
                'environment' => 'production',
            ]]),
        ]);

        $organization = app(KoamishinManagementClient::class)->getOrganization();

        $this->assertSame('10', $organization['id']);
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/oauth/token' && $request['client_id'] === 'management-id' && $request['scope'] === 'organization:read');
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/api/v1/organization' && $request->hasHeader('Authorization', 'Bearer machine-token'));
    }

    public function test_incomplete_management_credentials_do_not_fall_back_to_the_environment_secret(): void
    {
        Http::fake(['https://portal.test/*' => Http::response()]);

        foreach ([
            new KoamishinManagementClient('https://portal.test', clientId: 'management-id', secretKey: 'sk_live_backend_123'),
            new KoamishinManagementClient('https://portal.test', clientSecret: 'management-secret', secretKey: 'sk_live_backend_123'),
        ] as $client) {
            try {
                $client->listUsers();
                $this->fail('Incomplete scoped credentials fell back to the environment secret.');
            } catch (RuntimeException $exception) {
                $this->assertSame('Management API credentials are not configured.', $exception->getMessage());
            }
        }

        Http::assertNothingSent();
    }

    public function test_rejects_publishable_keys_for_management_authentication_before_sending_a_request(): void
    {
        Http::fake(['https://portal.test/*' => Http::response()]);

        foreach ([
            new KoamishinManagementClient('https://portal.test', secretKey: 'pk_test_123'),
            new KoamishinManagementClient('https://portal.test', secretKey: 'pk_live_123'),
            new KoamishinManagementClient('https://portal.test', clientId: 'pk_live_123', clientSecret: 'management-secret'),
            new KoamishinManagementClient('https://portal.test', clientId: 'management-id', clientSecret: 'pk_test_123'),
        ] as $client) {
            try {
                $client->listUsers();
                $this->fail('A publishable key was accepted for Management API authentication.');
            } catch (RuntimeException $exception) {
                $this->assertSame('A Koamishin publishable key cannot be used for Management API authentication.', $exception->getMessage());
            }
        }

        Http::assertNothingSent();
    }

    public function test_rejects_malformed_secret_keys_before_sending_a_request(): void
    {
        Http::fake(['https://portal.test/*' => Http::response()]);

        foreach (['sk_staging_123', 'sk_live_', 'invalid-secret', 'sk_test_bad space'] as $secretKey) {
            try {
                (new KoamishinManagementClient('https://portal.test', secretKey: $secretKey))->getOrganization();
                $this->fail('A malformed secret key was accepted.');
            } catch (RuntimeException $exception) {
                $this->assertSame('Invalid Koamishin secret key format.', $exception->getMessage());
            }
        }

        Http::assertNothingSent();
    }
}
