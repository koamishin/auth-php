<?php

declare(strict_types=1);

return [
    /*
     * The URL of your centralized Koamishin Portal instance.
     * (e.g. https://auth.yourcompany.com)
     */
    'portal_url' => env('KOAMISHIN_PORTAL_URL', 'http://localhost:8000'),

    /*
     * Client ID registered in Koamishin Portal (Filament OAuth Clients).
     */
    'client_id' => env('KOAMISHIN_CLIENT_ID', ''),

    /*
     * Client Secret registered in Koamishin Portal.
     */
    'client_secret' => env('KOAMISHIN_CLIENT_SECRET', ''),

    /*
     * Callback URL in this client application.
     * Must be whitelisted on Koamishin Portal.
     */
    'redirect_uri' => env('KOAMISHIN_REDIRECT_URI', 'http://localhost:3000/koamishin/callback'),

    /*
     * Bind accepted identities to this Portal application and environment.
     */
    'application_id' => env('KOAMISHIN_APPLICATION_ID', ''),
    'environment' => env('KOAMISHIN_ENVIRONMENT', ''),

    /* Redirect the application's standard login and registration pages to the Portal. */
    'hosted_auth_routes' => env('KOAMISHIN_HOSTED_AUTH_ROUTES', true),
    'hosted_return_to' => env('KOAMISHIN_HOSTED_RETURN_TO'),

    /*
     * Webhook secret for validating incoming user sync events.
     */
    'webhook_secret' => env('KOAMISHIN_WEBHOOK_SECRET', ''),

    // Legacy uses the literal secret. Standard expects a base64-encoded whsec_ secret.
    'webhook_format' => env('KOAMISHIN_WEBHOOK_FORMAT', 'legacy'),

    'scopes' => ['openid', 'profile', 'email', 'roles', 'metadata:public'],

    // Use separate client-credentials credentials for the management API.
    'management_client_id' => env('KOAMISHIN_MANAGEMENT_CLIENT_ID', ''),
    'management_client_secret' => env('KOAMISHIN_MANAGEMENT_CLIENT_SECRET', ''),
];
