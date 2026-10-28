<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use Illuminate\Contracts\Auth\Authenticatable;

class KoamishinUser implements Authenticatable
{
    /**
     * @param  array<string>  $roles
     * @param  array<string>  $permissions
     */
    public function __construct(
        public string $id,
        public string $name,
        public string $email,
        public bool $emailVerified = false,
        public ?string $picture = null,
        public array $roles = [],
        public array $permissions = [],
        public ?int $updatedAt = null,
        public ?string $username = null,
        public ?string $phoneNumber = null,
        public bool $phoneVerified = false,
        public ?string $web3Wallet = null,
        public ?array $metadata = null,
        public ?array $publicMetadata = null,
        public ?string $organizationId = null,
        public ?string $applicationId = null,
        public ?string $environment = null,
    ) {}

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: (string) ($data['sub'] ?? $data['id'] ?? ''),
            name: (string) ($data['name'] ?? ''),
            email: (string) ($data['email'] ?? ''),
            emailVerified: (bool) ($data['email_verified'] ?? false),
            picture: $data['picture'] ?? $data['profile_photo_url'] ?? null,
            roles: is_array($data['roles'] ?? null) ? $data['roles'] : [],
            permissions: is_array($data['permissions'] ?? null) ? $data['permissions'] : [],
            updatedAt: isset($data['updated_at']) ? (is_numeric($data['updated_at']) ? (int) $data['updated_at'] : (strtotime((string) $data['updated_at']) ?: null)) : null,
            username: isset($data['preferred_username']) ? (string) $data['preferred_username'] : null,
            phoneNumber: isset($data['phone_number']) ? (string) $data['phone_number'] : null,
            phoneVerified: (bool) ($data['phone_number_verified'] ?? false),
            web3Wallet: isset($data['web3_wallet']) ? (string) $data['web3_wallet'] : null,
            metadata: is_array($data['metadata'] ?? null) ? $data['metadata'] : null,
            publicMetadata: is_array($data['public_metadata'] ?? null) ? $data['public_metadata'] : null,
            organizationId: isset($data['organization_id']) ? (string) $data['organization_id'] : null,
            applicationId: isset($data['application_id']) ? (string) $data['application_id'] : null,
            environment: isset($data['environment']) ? (string) $data['environment'] : null,
        );
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles, true);
    }

    public function can(string $permission): bool
    {
        return in_array($permission, $this->permissions, true);
    }

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function getAuthIdentifier(): string
    {
        return $this->id;
    }

    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    public function getAuthPassword(): string
    {
        return '';
    }

    public function getRememberToken(): ?string
    {
        return null;
    }

    public function setRememberToken(mixed $value): void {}

    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }
}
