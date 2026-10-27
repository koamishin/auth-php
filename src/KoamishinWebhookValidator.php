<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use Illuminate\Http\Request;

class KoamishinWebhookValidator
{
    /**
     * Validate incoming webhook from Koamishin Portal (Svix standard).
     */
    public static function isValid(Request $request, string $secret, int $tolerance = 300): bool
    {
        $id = $request->header('svix-id');
        $timestamp = $request->header('svix-timestamp');
        $signature = $request->header('svix-signature');

        if (! $id || ! $timestamp || ! $signature) {
            return false;
        }

        if (abs(time() - (int) $timestamp) > $tolerance) {
            return false;
        }

        $body = $request->getContent();
        $toSign = "{$id}.{$timestamp}.{$body}";
        $expectedSignature = 'v1,'.base64_encode(hash_hmac('sha256', $toSign, $secret, true));

        return hash_equals($expectedSignature, $signature);
    }
}
