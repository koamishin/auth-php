# Koamishin Auth PHP SDK

[![Latest Version on Packagist](https://img.shields.io/packagist/v/koamishin/auth-php.svg?style=flat-square)](https://packagist.org/packages/koamishin/auth-php)
[![Total Downloads](https://img.shields.io/packagist/dt/koamishin/auth-php.svg?style=flat-square)](https://packagist.org/packages/koamishin/auth-php)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)
[![PHP Version](https://img.shields.io/badge/php-%5E8.2-blue.svg?style=flat-square)](composer.json)

Official PHP and Laravel SDK for connecting internal company applications to **Koamishin Portal** — a centralized, self-hostable identity management system operating like Clerk and Google Auth with OAuth2, OpenID Connect (OIDC), and PKCE.

---

## Features

- **Clerk-like Experience**: One-line redirects to centralized hosted auth with automatic return callback.
- **PKCE Security**: High-security RFC 7636 Authorization Code Grant with SHA-256 code challenge.
- **Role & Permission Aware**: Synchronizes Spatie roles and permissions across downstream internal tools.
- **Route Middleware**: Protect web routes and APIs with `AuthenticateWithKoamishin` and role parameters.
- **Realtime Webhooks**: Validate Svix-standard HMAC-SHA256 signatures for `user.created`, `user.updated`, and `user.deleted` events.

---

## Requirements

- PHP 8.2, 8.3, 8.4, or 8.5
- Laravel 10.x, 11.x, 12.x, or 13.x

---

## Installation

Install the package via Composer:

```bash
composer require koamishin/auth-php
```

Publish the configuration file:

```bash
php artisan vendor:publish --tag=koamishin-config
```

---

## Configuration

Add your Koamishin Portal credentials to your client application's `.env` file:

```env
# URL of your Koamishin Portal instance
KOAMISHIN_PORTAL_URL=https://auth.company.internal

# Client ID generated in Koamishin Admin Panel (OAuth Applications)
KOAMISHIN_CLIENT_ID=01a17b...

# Client Secret generated in Koamishin Admin Panel
KOAMISHIN_CLIENT_SECRET=secret_...

# Whitelisted callback URL on this client app
KOAMISHIN_REDIRECT_URI=https://crm.company.internal/koamishin/callback

# Webhook signing secret from Webhook Endpoints in Portal
KOAMISHIN_WEBHOOK_SECRET=whsec_...
```

The published `config/koamishin.php` file reads these variables:

```php
return [
    'portal_url' => env('KOAMISHIN_PORTAL_URL', 'http://localhost:8000'),
    'client_id' => env('KOAMISHIN_CLIENT_ID', ''),
    'client_secret' => env('KOAMISHIN_CLIENT_SECRET', ''),
    'redirect_uri' => env('KOAMISHIN_REDIRECT_URI', ''),
    'webhook_secret' => env('KOAMISHIN_WEBHOOK_SECRET', ''),
];
```

---

## Usage in Laravel

### 1. Register Auth Routes

In your client application's `routes/web.php`:

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Koamishin\Auth\Facades\Koamishin;

// 1. Redirect user to Koamishin Portal
Route::get('/login', function () {
    return redirect()->away(Koamishin::getLoginUrl());
})->name('login');

// 2. Handle callback after successful portal authentication
Route::get('/koamishin/callback', function (Request $request) {
    $user = Koamishin::handleCallback(
        code: (string) $request->query('code'),
        state: (string) $request->query('state'),
    );

    // Access user claims
    // $user->id
    // $user->name
    // $user->email
    // $user->roles
    // $user->permissions

    return redirect('/dashboard');
});

// 3. Logout
Route::post('/logout', function () {
    Koamishin::logout();
    return redirect('/');
})->name('logout');
```

---

### 2. Protecting Routes with Middleware

Protect routes using the `AuthenticateWithKoamishin` middleware:

```php
use App\Http\Controllers\DashboardController;
use Koamishin\Auth\Middleware\AuthenticateWithKoamishin;

// Any logged-in Koamishin user
Route::middleware(AuthenticateWithKoamishin::class)->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index']);
});

// Require specific role (e.g., admin or manager)
Route::middleware(AuthenticateWithKoamishin::class . ':admin')->group(function () {
    Route::get('/admin/billing', [BillingController::class, 'index']);
});
```

---

### 3. Accessing Authenticated User

```php
use Koamishin\Auth\Facades\Koamishin;

// Check if logged in
if (Koamishin::check()) {
    $user = Koamishin::user();

    $name = $user->name;
    $email = $user->email;

    // Check roles and permissions
    if ($user->hasRole('admin')) {
        // Admin actions
    }

    if ($user->can('publish-posts')) {
        // Authorized
    }
}
```

---

### 4. Realtime User Sync Webhook

Koamishin Portal dispatches Svix-standard webhooks whenever users are created, updated, or deleted. Verify incoming payloads with `KoamishinWebhookValidator`:

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Koamishin\Auth\KoamishinWebhookValidator;

Route::post('/api/webhooks/koamishin', function (Request $request) {
    $secret = config('koamishin.webhook_secret');

    // 1. Verify Svix HMAC-SHA256 signature
    if (! KoamishinWebhookValidator::isValid($request, $secret)) {
        return response()->json(['error' => 'Invalid webhook signature.'], 401);
    }

    $event = $request->json('type'); // user.created, user.updated, user.deleted
    $data = $request->json('data');

    match ($event) {
        'user.created', 'user.updated' => \App\Models\User::updateOrCreate(
            ['koamishin_id' => $data['id']],
            [
                'name' => $data['name'],
                'email' => $data['email'],
            ]
        ),
        'user.deleted' => \App\Models\User::where('koamishin_id', $data['id'])->delete(),
        default => null,
    };

    return response()->json(['status' => 'success']);
});
```

---

## API Reference

### `Koamishin` Facade

| Method | Returns | Description |
| :--- | :--- | :--- |
| `getLoginUrl(?string $returnTo = null)` | `string` | Generates PKCE code challenge and returns portal authorization redirect URL. |
| `handleCallback(string $code, string $state)` | `KoamishinUser` | Exchanges authorization code for tokens, verifies state, and returns user. |
| `user()` | `?KoamishinUser` | Returns currently logged-in user or `null`. |
| `check()` | `bool` | Returns `true` if current session is authenticated. |
| `logout()` | `void` | Clears local Koamishin session tokens. |

### `KoamishinUser` Object

| Property / Method | Type | Description |
| :--- | :--- | :--- |
| `$user->id` | `string` | Central Koamishin User ID (`sub`). |
| `$user->name` | `string` | Full user name. |
| `$user->email` | `string` | Primary verified email address. |
| `$user->emailVerified` | `bool` | Email verification flag. |
| `$user->picture` | `?string` | Profile photo URL. |
| `$user->roles` | `array<string>` | Spatie roles assigned in Portal. |
| `$user->permissions` | `array<string>` | Permissions assigned in Portal. |
| `$user->hasRole(string $role)` | `bool` | Check if user possesses given role. |
| `$user->can(string $permission)` | `bool` | Check if user has given permission. |

---

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
