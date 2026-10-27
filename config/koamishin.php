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
     * Webhook secret for validating incoming user sync events.
     */
    'webhook_secret' => env('KOAMISHIN_WEBHOOK_SECRET', ''),
];
