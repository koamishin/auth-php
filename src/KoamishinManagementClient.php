<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use Illuminate\Support\Facades\Http;
use InvalidArgumentException;
use RuntimeException;

class KoamishinManagementClient
{
    public function __construct(
        protected string $portalUrl,
        protected string $clientId,
        protected string $clientSecret,
    ) {
        $this->portalUrl = rtrim($portalUrl, '/');
    }

    /**
     * @return array{id: string, name: string, slug: string, application_id: string, environment: string}
     */
    public function getOrganization(): array
    {
        $data = $this->request('GET', '/api/v1/organization', 'organization:read')['data'] ?? null;

        if (! is_array($data)
            || ! is_string($data['id'] ?? null)
            || ! is_string($data['name'] ?? null)
            || ! is_string($data['slug'] ?? null)
            || ! is_string($data['application_id'] ?? null)
            || ! is_string($data['environment'] ?? null)) {
            throw new RuntimeException('Portal returned an invalid organization.');
        }

        return [
            'id' => $data['id'],
            'name' => $data['name'],
            'slug' => $data['slug'],
            'application_id' => $data['application_id'],
            'environment' => $data['environment'],
        ];
    }

    /**
     * @return array{data: list<KoamishinUser>, links: array<string, mixed>, meta: array<string, mixed>}
     */
    public function listUsers(int $page = 1, int $perPage = 15): array
    {
        $this->validatePagination($page, $perPage);

        $data = $this->request('GET', '/api/v1/users', 'users:read', ['page' => $page, 'per_page' => $perPage]);
        if (! is_array($data['data'] ?? null) || ! is_array($data['links'] ?? null) || ! is_array($data['meta'] ?? null)) {
            throw new RuntimeException('Portal returned an invalid user list.');
        }

        return [
            'data' => array_map(fn (array $user): KoamishinUser => KoamishinUser::fromArray($user), $data['data']),
            'links' => $data['links'],
            'meta' => $data['meta'],
        ];
    }

    public function getUser(string $id): KoamishinUser
    {
        $data = $this->request('GET', '/api/v1/users/'.$this->encodedId($id), 'users:read');
        if (! is_array($data['data'] ?? null)) {
            throw new RuntimeException('Portal returned an invalid user.');
        }

        return KoamishinUser::fromArray($data['data']);
    }

    /**
     * Enroll an existing organization member in this application environment.
     */
    public function enrollUserInApplication(string $id): void
    {
        $this->request('PUT', '/api/v1/users/'.$this->encodedId($id).'/membership', 'memberships:write');
    }

    /**
     * Remove an application-environment membership and revoke its OAuth grants.
     */
    public function removeUserFromApplication(string $id): void
    {
        $this->request('DELETE', '/api/v1/users/'.$this->encodedId($id).'/membership', 'memberships:write');
    }

    /**
     * List active OAuth grants for this application's environment. Grant IDs
     * change when the user refreshes the access token.
     *
     * @return array{data: list<array<string, mixed>>, links: array<string, mixed>, meta: array<string, mixed>}
     */
    public function listUserSessions(string $id, int $page = 1, int $perPage = 15): array
    {
        $this->validatePagination($page, $perPage);
        $data = $this->request('GET', '/api/v1/users/'.$this->encodedId($id).'/sessions', 'sessions:read', [
            'page' => $page,
            'per_page' => $perPage,
        ]);

        if (! is_array($data['data'] ?? null) || ! is_array($data['links'] ?? null) || ! is_array($data['meta'] ?? null)) {
            throw new RuntimeException('Portal returned an invalid session list.');
        }

        return ['data' => $data['data'], 'links' => $data['links'], 'meta' => $data['meta']];
    }

    /**
     * Revoke a single OAuth grant and its refresh tokens. This does not end
     * the user's Portal browser session or sessions in other applications.
     */
    public function revokeUserSession(string $id, string $sessionId): void
    {
        $this->request('DELETE', '/api/v1/users/'.$this->encodedId($id).'/sessions/'.$this->encodedId($sessionId, 'session'), 'sessions:revoke');
    }

    /**
     * @return array{public: array<string, mixed>, private: array<string, mixed>}
     */
    public function getUserMetadata(string $id): array
    {
        return $this->metadataResponse($this->request('GET', '/api/v1/users/'.$this->encodedId($id).'/metadata', 'metadata:read'));
    }

    /**
     * Each provided bucket replaces that bucket; null leaves it unchanged.
     *
     * @param  array<string, mixed>|null  $public
     * @param  array<string, mixed>|null  $private
     * @return array{public: array<string, mixed>, private: array<string, mixed>}
     */
    public function updateUserMetadata(string $id, ?array $public = null, ?array $private = null): array
    {
        if ($public === null && $private === null) {
            throw new InvalidArgumentException('Provide at least one metadata bucket.');
        }

        $payload = [];
        if ($public !== null) {
            $payload['public'] = (object) $public;
        }
        if ($private !== null) {
            $payload['private'] = (object) $private;
        }

        return $this->metadataResponse($this->request('PATCH', '/api/v1/users/'.$this->encodedId($id).'/metadata', 'metadata:read metadata:write', $payload));
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    protected function request(string $method, string $path, string $scope, array $payload = []): array
    {
        if ($this->portalUrl === '' || $this->clientId === '' || $this->clientSecret === '') {
            throw new RuntimeException('Management API credentials are not configured.');
        }

        $tokenResponse = Http::connectTimeout(3)->timeout(10)->asForm()->post("{$this->portalUrl}/oauth/token", [
            'grant_type' => 'client_credentials',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'scope' => $scope,
        ]);
        $token = $tokenResponse->json('access_token');
        if (! $tokenResponse->successful() || ! is_string($token) || $token === '') {
            throw new RuntimeException('Management API token request failed.');
        }

        $client = Http::connectTimeout(3)->timeout(10)->acceptJson()->withToken($token);
        $response = match ($method) {
            'GET' => $client->get($this->portalUrl.$path, $payload),
            'PATCH' => $client->patch($this->portalUrl.$path, $payload),
            'PUT' => $client->send('PUT', $this->portalUrl.$path),
            'DELETE' => $client->delete($this->portalUrl.$path),
            default => throw new InvalidArgumentException('Unsupported management API method.'),
        };
        if (! $response->successful()) {
            throw new RuntimeException('Management API request failed with status '.$response->status().'.');
        }

        if (in_array($method, ['PUT', 'DELETE'], true) && $response->status() === 204) {
            return [];
        }

        $data = $response->json();
        if (! is_array($data)) {
            throw new RuntimeException('Portal returned invalid JSON.');
        }

        return $data;
    }

    protected function encodedId(string $id, string $type = 'user'): string
    {
        if ($id === '') {
            throw new InvalidArgumentException('A '.$type.' ID is required.');
        }

        return rawurlencode($id);
    }

    protected function validatePagination(int $page, int $perPage): void
    {
        if ($page < 1 || $perPage < 1 || $perPage > 100) {
            throw new InvalidArgumentException('Invalid pagination parameters.');
        }
    }

    /**
     * @param  array<string, mixed>  $response
     * @return array{public: array<string, mixed>, private: array<string, mixed>}
     */
    protected function metadataResponse(array $response): array
    {
        $data = $response['data'] ?? null;
        if (! is_array($data) || ! is_array($data['public'] ?? null) || ! is_array($data['private'] ?? null)) {
            throw new RuntimeException('Portal returned invalid metadata.');
        }

        return ['public' => $data['public'], 'private' => $data['private']];
    }
}
