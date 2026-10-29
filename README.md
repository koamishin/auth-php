# Koamishin Auth for Laravel

The Koamishin PHP SDK connects a Laravel application to a Koamishin Portal. It provides an OAuth 2.0 authorization-code login with PKCE, a Laravel request guard, a server-side management client, and webhook signature verification.

The features in this README describe the source in this checkout. A package version already published on Packagist may not include them; check the version you install. The package declares support for PHP 8.2–8.5 and Laravel's Illuminate components 10–13; those constraints are not a guarantee that every combination has been tested.

## Before you begin

1. Deploy a Portal version that includes the SDK's application-scoped API. Create an organization, an application, and the desired `development` or `production` environment.
2. Create an authorization-code OAuth client for that application environment. Register the **exact** callback URL of your Laravel app. Enroll the user in both the organization and that application environment, or explicitly enable the Portal environment's self-service enrollment policy.
3. Create a separate management client if your server needs to read users or manage metadata. Authorization-code credentials and management credentials are not interchangeable.
4. Use HTTPS for the Portal and the client application in production. Configure Laravel's application key, a session store, and secure session cookies. Never expose either client secret in frontend JavaScript, a mobile app, a repository, or a URL.

The Portal and application need a working network connection. Each authenticated request revalidates the current access token with the Portal; an unavailable Portal results in an error rather than trusting old session claims.

## Install and configure

Install a package version that contains the features you need:

```bash
composer require koamishin/auth-php
php artisan vendor:publish --tag=koamishin-config
```

Until a tagged release containing these features is published, a normal stable install may select an older version. For development, after the updated SDK branch is available on GitHub, a consuming project can use its development branch explicitly:

```bash
composer config repositories.koamishin-auth vcs https://github.com/koamishin/auth-php.git
composer require koamishin/auth-php:dev-main
```

Commit the consuming project's lockfile to pin the resolved revision, and use a reviewed release for production.

Add the application environment's **authorization-code** credentials to the Laravel app's `.env`:

```dotenv
KOAMISHIN_PORTAL_URL=https://auth.example.com
KOAMISHIN_CLIENT_ID=your-authorization-code-client-id
KOAMISHIN_CLIENT_SECRET=your-authorization-code-client-secret
KOAMISHIN_REDIRECT_URI=https://app.example.com/koamishin/callback
KOAMISHIN_APPLICATION_ID=123
KOAMISHIN_ENVIRONMENT=production
```

Set `KOAMISHIN_APPLICATION_ID` to the application's Portal ID and `KOAMISHIN_ENVIRONMENT` to `development` or `production`. They must match the OAuth client's environment. On every userinfo response the SDK checks both claims, preventing an otherwise valid token issued to another application or environment from authenticating here. Both values are required. Existing installations need these environment variables and should verify their published `config/koamishin.php` exposes `application_id` and `environment`.

The SDK reads these values through `config/koamishin.php`; refresh Laravel's configuration cache after changing deployment configuration. The default requested scopes are `openid`, `profile`, `email`, `roles`, and `metadata:public`. Change the `scopes` array in the published configuration if your application requires a different set. The Portal only includes optional claims when the corresponding scope was granted.

Register the guard in `config/auth.php`:

```php
'guards' => [
    // Your other guards...
    'koamishin' => [
        'driver' => 'koamishin',
    ],
],
```

The SDK registers its provider automatically in a standard Laravel installation. When an authorization client is configured, it redirects the application's `/login` and `/register` web routes to the Portal, including when the application already defines those routes. Local POST requests to those two routes are rejected. It does not create a callback route, views, or local user records for you.

Set `KOAMISHIN_HOSTED_RETURN_TO=/dashboard` to choose a local path after sign-in, or pass a local `return_to` query parameter on the application's login or registration URL. External return URLs are rejected. To keep existing application routes instead, set `KOAMISHIN_HOSTED_AUTH_ROUTES=false` and define the redirects yourself. Refresh the configuration and route caches after changing these settings.

## Sign in and protect routes

Add the callback and protected routes to your application's `routes/web.php`. These routes require Laravel's `web` middleware because the OAuth transaction and resulting tokens live in the session. The SDK supplies the standard `login` and `register` entry points.

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Koamishin\Auth\Facades\Koamishin;

Route::get('/koamishin/callback', function (Request $request) {
    if ($request->query('error')) {
        abort(403, 'Sign-in was not completed.');
    }

    $input = $request->validate([
        'code' => ['required', 'string'],
        'state' => ['required', 'string'],
    ]);

    try {
        Koamishin::handleCallback($input['code'], $input['state']);
    } catch (InvalidArgumentException $exception) {
        abort(403, 'Invalid or expired sign-in request.');
    }

    return redirect()->to(Koamishin::consumeReturnTo('/dashboard'));
})->name('koamishin.callback');

Route::get('/dashboard', function (Request $request) {
    $user = $request->user(); // KoamishinUser

    return response()->json([
        'id' => $user->id,
        'name' => $user->name,
        'email' => $user->email,
        'public_metadata' => $user->publicMetadata,
    ]);
})->middleware('auth:koamishin');

Route::post('/logout', function () {
    Koamishin::logout();

    return redirect('/');
})->name('logout');
```

Submit the logout route from a POST form with Laravel's `@csrf` directive. Logout clears the local application's Koamishin session and rotates its session ID. It does **not** revoke the Portal token or end the user's Portal browser session.

`getLoginUrl()` stores a random state and PKCE verifier in the session. `getRegistrationUrl()` creates the same OAuth transaction and adds `screen_hint=signup`, allowing the Portal to show the requesting application's registration page and retain its callback. Use this method for an app's Register link: a redirect straight to the generic Portal `/register` page does not start an OAuth transaction and cannot authenticate the user back to that app.

By default, each new application login requires authentication on the Portal, even when the browser has a Portal session or is signed into another application. Administrators can opt applications into SSO in the Portal. The SDK maintains a separate local session for each consuming application; a local logout does not log the user out of the other applications. When using social login, the external provider may reuse its own session.

The Portal validates the client and callback and applies the selected environment's enrollment policy. With self-service enrollment enabled, a new account can register and authorize the requesting application, then return through the same callback. Other applications and environments keep their own memberships and metadata. A closed application requires operator enrollment. Registration does not let the browser assign private metadata, application roles, or permissions.

`handleCallback()` validates and consumes the OAuth state, exchanges the code, rotates the session ID, and stores encrypted access and refresh tokens. `user()` rechecks userinfo and refreshes an expired access token when possible. If the Portal denies the token, the local Koamishin session is cleared. Protect the session and `APP_KEY`; rotating the application key invalidates the encrypted tokens.

`consumeReturnTo()` only accepts local paths, falling back to `/` when necessary. Avoid overriding that check with an arbitrary `redirect()->away()` based on user input. When concurrent requests can refresh the same session, use Laravel session blocking with a shared lock-capable cache for the relevant routes; otherwise concurrent session writes or refreshes can race.

For JSON API routes, `auth:koamishin` also accepts an `Authorization: Bearer <access-token>` header and validates it against the Portal. A request carrying an invalid bearer token is not allowed to fall back to a browser session. The guard provides a `KoamishinUser` implementing Laravel's authentication contract, not an Eloquent model; map the Portal user ID to a local model yourself if your application requires one.

## Maintain a local Eloquent user projection

Keep `KoamishinUser` as the authenticated Portal principal. If your application needs normal Eloquent relationships, create a local `users` row after the callback and identify it by a unique `koamishin_user_id`. This example assumes each application and environment has its own local database. The local row is a projection of selected Portal profile fields; it does not replace Portal authentication or store Portal passwords and tokens. App-owned records continue to reference the local `users.id`.

Add a nullable external ID and the app/environment context to the local table. The sample requires the `email` claim because its local `users.email` column is required. Request the `email` scope and reject sign-in when that claim is empty. If the app only accepts Koamishin sign-in, make its local password column nullable as well; never copy or generate a password from Portal credentials. Before rolling back that migration, assign local passwords or remove passwordless projection rows so the original non-null password constraint can be restored.

```php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

Schema::table('users', function (Blueprint $table) {
    $table->string('koamishin_user_id')->nullable()->unique();
    $table->string('koamishin_application_id')->nullable();
    $table->string('koamishin_environment')->nullable();
    $table->json('koamishin_public_metadata')->nullable();
    $table->string('password')->nullable()->change();
});
```

Allow the projection fields in your local `User` model's mass-assignment configuration. The example below uses the Laravel 10–12 `$fillable` property; Laravel 13 also supports the `#[Fillable([...])]` model attribute used by the App A and App B examples. Cast public metadata to an array, and keep each application's usual relationships on that Eloquent model:

```php
use App\Models\Post;
use Illuminate\Database\Eloquent\Relations\HasMany;

protected $fillable = [
    'name',
    'email',
    'email_verified_at',
    'koamishin_user_id',
    'koamishin_application_id',
    'koamishin_environment',
    'koamishin_public_metadata',
];

protected function casts(): array
{
    return [
        'koamishin_public_metadata' => 'array',
    ];
}

public function posts(): HasMany
{
    return $this->hasMany(Post::class);
}
```

Use an app-level service to validate the configured application context and create or find the projection by the unique Portal subject. Laravel's `firstOrCreate` handles concurrent creation against that unique key. Do not find or link local users by email alone: if a local account already owns that email, require a trusted, explicit account-linking flow. Define the conflict exception used below:

```php
// app/Exceptions/KoamishinIdentityConflict.php
namespace App\Exceptions;

use RuntimeException;

final class KoamishinIdentityConflict extends RuntimeException {}
```

```php
use App\Exceptions\KoamishinIdentityConflict;
use App\Models\User;
use InvalidArgumentException;
use Koamishin\Auth\KoamishinUser;
use RuntimeException;

final class KoamishinUserProjector
{
    public function sync(KoamishinUser $identity): User
    {
        $applicationId = (string) config('koamishin.application_id');
        $environment = (string) config('koamishin.environment');

        if ($applicationId === '' || ! in_array($environment, ['development', 'production'], true)) {
            throw new RuntimeException('Configure the Koamishin application ID and environment.');
        }

        if ($identity->applicationId !== $applicationId || $identity->environment !== $environment) {
            throw new InvalidArgumentException('The Portal identity belongs to another application environment.');
        }

        if (trim($identity->email) === '') {
            throw new InvalidArgumentException('The Portal email claim is required; request the email scope.');
        }

        $emailOwner = User::query()->where('email', $identity->email)->first();

        if ($emailOwner !== null && $emailOwner->koamishin_user_id !== $identity->id) {
            throw new KoamishinIdentityConflict('A local account already uses this email; link it explicitly before sign-in.');
        }

        $localUser = User::query()->firstOrCreate(
            ['koamishin_user_id' => $identity->id],
            [
                'koamishin_application_id' => $identity->applicationId,
                'koamishin_environment' => $identity->environment,
                'koamishin_public_metadata' => $identity->publicMetadata,
                'name' => $identity->name,
                'email' => $identity->email,
            ],
        );

        $localUser->fill([
            'koamishin_user_id' => $identity->id,
            'koamishin_application_id' => $identity->applicationId,
            'koamishin_environment' => $identity->environment,
            'koamishin_public_metadata' => $identity->publicMetadata,
            'name' => $identity->name,
            'email' => $identity->email,
            'email_verified_at' => $identity->emailVerified ? ($localUser->email_verified_at ?? now()) : null,
        ]);

        if ($localUser->isDirty()) {
            $localUser->save();
        }

        return $localUser;
    }
}
```

Call the projector with the result of the verified callback to create the local row immediately. The example copies the central email verification state to Laravel's `email_verified_at` field, preserves the original verification timestamp, and clears it if the Portal says the email is unverified. Sync again on protected requests or handle signed user update webhooks when the app needs changes reflected during an existing session:

```php
use Koamishin\Auth\Facades\Koamishin;

$identity = Koamishin::handleCallback($input['code'], $input['state']);
$localUser = app(KoamishinUserProjector::class)->sync($identity);

$post = $localUser->posts()->create(['title' => 'App-owned content']);
```

Use `$request->user('koamishin')` for the current Portal identity and its app-scoped roles and permissions. Use the local `User` for app-owned Eloquent data. Public metadata is user-visible input and must not grant roles or permissions; keep private metadata behind the scoped management API. On an email conflict, clear the SDK session with `Koamishin::logout()` before returning an error. For a database shared across applications or environments, adapt the schema and every lookup to use a composite key of Portal user ID, application ID, and environment; the single-key code above is for an app-specific database.

The package also ships optional role-checking middleware:

```php
use Koamishin\Auth\Middleware\AuthenticateWithKoamishin;

Route::get('/reports', fn (Request $request) => $request->user()->name)
    ->middleware(AuthenticateWithKoamishin::class.':member');
```

The role is the user's role in this application environment, not a global Portal administrator role. Ask for the `roles` scope when using role checks. Applications still need their own authorization policies for sensitive actions.

## Read users and manage metadata

Create a **separate** client-credentials client on the Portal host. The command takes an application ID and one environment; issue only the scopes needed by the service:

```bash
php artisan koamishin:management-client 123 production \
  --scope=users:read --scope=metadata:read --scope=metadata:write
```

Store the generated credentials securely when they are presented and add them to the Laravel server's `.env`:

```dotenv
KOAMISHIN_MANAGEMENT_CLIENT_ID=your-management-client-id
KOAMISHIN_MANAGEMENT_CLIENT_SECRET=your-management-client-secret
```

Resolve the client through Laravel's container:

```php
use Koamishin\Auth\KoamishinManagementClient;

$portal = app(KoamishinManagementClient::class);

$page = $portal->listUsers(page: 1, perPage: 25); // data, links, meta
foreach ($page['data'] as $user) {
    echo $user->id;
}

$user = $portal->getUser('42');
$metadata = $portal->getUserMetadata($user->id);

$metadata = $portal->updateUserMetadata(
    $user->id,
    public: ['department' => 'Support', 'preferences' => ['theme' => 'dark']],
    private: ['internal_customer_number' => 'C-123'],
);
```

`listUsers()` and `getUser()` require `users:read`. `getUserMetadata()` requires `metadata:read`. Updating metadata requires both `metadata:read` and `metadata:write` because the response returns both buckets. The API addresses only users enrolled in the client's application environment.

To read the organization attached to the management client's environment, grant `organization:read` and call `$portal->getOrganization()`. The result contains `id`, `name`, `slug`, `application_id`, and `environment`.

Each supplied metadata bucket **replaces** the entire bucket; an omitted argument leaves that bucket unchanged. Passing `public: []` clears the public bucket. Read and merge values yourself when replacing one key, and coordinate concurrent writes in your own application. The combined public and private values cannot exceed 16 KiB. Both buckets must be JSON objects; use associative PHP arrays for object values.

Public metadata is visible to a signed-in client that receives the `metadata:public` scope. Treat it as user-visible data. Private metadata is available to management clients with the proper scope; it is access-controlled but is not automatically encrypted in the Portal database. Do not put secrets into either bucket. Metadata is scoped separately for every application environment.

## Manage application membership

With a management client granted `memberships:write`, enroll an existing organization member in the bound application environment:

```php
use Koamishin\Auth\KoamishinManagementClient;

$portal = app(KoamishinManagementClient::class);
$portal->enrollUserInApplication('42');
$portal->removeUserFromApplication('42');
```

Enrollment is idempotent and assigns the `member` role. Removal revokes that application's access and refresh tokens. It does not delete the user, their organization membership, other environment memberships, or existing scoped metadata. The user must already belong to the organization. An out-of-organization user or removal of a missing membership returns `404`; an ambiguous authorization client returns `409`.

## List and revoke application grants

To manage a user's OAuth grants for this application environment, provision the management client with the separate `sessions:read` and/or `sessions:revoke` scopes. They can be passed to the client-creation command as `--scope=sessions:read --scope=sessions:revoke`.

```php
use Koamishin\Auth\KoamishinManagementClient;

$portal = app(KoamishinManagementClient::class);
$sessions = $portal->listUserSessions('42', page: 1, perPage: 25);

foreach ($sessions['data'] as $session) {
    echo $session['id'];
    echo $session['access_expires_at'];
}

if ($sessions['data'] !== []) {
    $portal->revokeUserSession('42', $sessions['data'][0]['id']);
}
```

The list includes grants with an active access or refresh token. Revoking a grant also revokes its related refresh tokens. The ID is an OAuth access-token identifier and changes when that grant is refreshed, so list grants again if an ID becomes stale. Revocation applies only to the selected application environment; it does not end the Portal's own browser session or sessions in other applications. A `409` response means the environment has no uniquely configured active authorization client.

## Verify and process webhooks

Create a Portal webhook endpoint for the intended application environment. Set its signing format and save its secret in the receiving Laravel application's `.env`:

```dotenv
KOAMISHIN_WEBHOOK_SECRET=your-webhook-signing-secret
KOAMISHIN_WEBHOOK_FORMAT=legacy
```

`legacy` treats the complete secret as the HMAC key and verifies the `svix-id`, `svix-timestamp`, and `svix-signature` headers. `standard` expects a `whsec_` prefix followed by a base64-encoded key and verifies `webhook-id`, `webhook-timestamp`, and `webhook-signature`; a complete Svix header set is accepted as a fallback when the standard set is incomplete. Header sets are never mixed, and a complete but invalid standard set is rejected rather than falling back. Both formats sign the raw request body and enforce a timestamp tolerance. Select the format in both Portal and SDK; existing endpoints continue using `legacy` until explicitly changed. The SDK never falls back between formats.

Register a POST route in your stateless API route file (commonly `routes/api.php`, with Laravel's `/api` prefix). Configure that route file in your Laravel application if it is not enabled. API routes do not use web-session CSRF protection; do not disable CSRF globally.

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Koamishin\Auth\KoamishinWebhookProcessor;
use Koamishin\Auth\KoamishinWebhookValidator;

Route::post('/webhooks/koamishin', function (Request $request) {
    $secret = config('koamishin.webhook_secret');
    $format = config('koamishin.webhook_format');

    $deliveryId = KoamishinWebhookValidator::verifiedDeliveryId($request, $secret, format: $format);
    if ($deliveryId === null) {
        abort(400, 'Invalid webhook signature.');
    }

    KoamishinWebhookProcessor::processOnce(
        $request,
        $secret,
        function (Request $verifiedRequest) use ($deliveryId): void {
            $event = $verifiedRequest->json()->all();

            // Replace this with idempotent application-specific event handling.
            Log::info('Koamishin webhook received', [
                'delivery_id' => $deliveryId,
                'type' => $event['type'] ?? 'unknown',
            ]);
        },
        format: $format,
        namespace: 'my-app-production',
        retentionSeconds: 86400,
        lockSeconds: 120,
    );

    return response()->noContent();
});
```

Configure a persistent, shared cache store with atomic lock support for all application instances before using `processOnce()`. The `array` cache is suitable only for tests. Use a distinct namespace per receiving application environment, retain processed IDs for at least the webhook retry window and twice the timestamp tolerance, and set `lockSeconds` longer than the maximum handler duration. Handler exceptions propagate so the sender can retry. A duplicate already recorded as successful returns `false` without invoking the handler.

This replay helper reduces duplicate processing; it cannot guarantee exactly-once side effects. A process may fail after performing an action but before recording the delivery, or a lock may expire. Make the business operation idempotent, ideally by recording the delivery ID transactionally with your application changes.

## Limits and troubleshooting

- The Portal supports OAuth 2.0 authorization-code login and userinfo. It does **not** currently issue OIDC ID tokens or provide complete OpenID Connect conformance; do not validate or rely on an `id_token` from this integration.
- User management currently provides read access, metadata replacement, and application-scoped OAuth grant listing/revocation; it does not provide general user creation, deletion, or a global sign-out API.
- A `401` or `403` from userinfo can indicate a revoked token, an inactive OAuth client/environment, or missing organization/application membership. Enroll the user in the correct environment and retry login.
- A `403` from the management API can indicate missing scopes, revoked credentials, or a disabled environment. A `404` may mean the user is not in that environment. Keep management credentials on the server.
- An invalid webhook signature can indicate the wrong endpoint secret, mismatched `legacy`/`standard` formats, a changed body, missing headers, or clock skew. Verify the raw body before modifying it.

MIT licensed; see [LICENSE](LICENSE).
