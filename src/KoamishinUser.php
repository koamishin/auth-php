<?php

declare(strict_types=1);

namespace Koamishin\Auth;

class KoamishinUser
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
        );
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles, true);
    }

    public function can(string $permission): bool
    {
        return in_array($permission, $this->permissions, true) || $this->hasRole('super_admin');
    }
}
