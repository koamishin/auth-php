<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use Illuminate\Http\Request;

class KoamishinWebhookValidator
{
    /**
     * Validate a Koamishin webhook using the configured signature format.
     */
    public static function isValid(Request $request, string $secret, int $tolerance = 300, string $format = 'legacy'): bool
    {
        return self::verifiedDeliveryId($request, $secret, $tolerance, $format) !== null;
    }

    /**
     * Return the verified delivery ID, or null if the signature is invalid.
     * Standard headers take priority when complete. Svix aliases are accepted
     * as a complete fallback set; headers from different sets are never mixed.
     */
    public static function verifiedDeliveryId(Request $request, string $secret, int $tolerance = 300, string $format = 'legacy'): ?string
    {
        $headers = self::headers($request, $format);

        if ($headers === null) {
            return null;
        }

        [$id, $timestamp, $signature] = $headers;

        if (! is_string($id) || $id === '' || ! is_string($timestamp) || ! ctype_digit($timestamp) || strlen($timestamp) > 12 || ! is_string($signature) || $signature === '' || $tolerance < 0) {
            return null;
        }

        if (abs(time() - (int) $timestamp) > $tolerance) {
            return null;
        }

        if ($format === 'legacy') {
            if (trim($secret) === '' || preg_match('/[\x00-\x1f\x7f]/', $secret)) {
                return null;
            }
            $key = $secret;
        } elseif ($format === 'standard') {
            if (! str_starts_with($secret, 'whsec_')) {
                return null;
            }

            $key = base64_decode(substr($secret, 6), true);
            if ($key === false || strlen($key) < 16) {
                return null;
            }
        } else {
            return null;
        }

        $body = $request->getContent();
        $toSign = "{$id}.{$timestamp}.{$body}";
        $expectedSignature = 'v1,'.base64_encode(hash_hmac('sha256', $toSign, $key, true));

        foreach (preg_split('/\s+/', trim($signature)) ?: [] as $candidate) {
            if (hash_equals($expectedSignature, $candidate)) {
                return $id;
            }
        }

        return null;
    }

    /**
     * @return array{string, string, string}|null
     */
    private static function headers(Request $request, string $format): ?array
    {
        $prefixes = match ($format) {
            'standard' => ['webhook', 'svix'],
            'legacy' => ['svix'],
            default => [],
        };

        foreach ($prefixes as $prefix) {
            $id = $request->header($prefix.'-id');
            $timestamp = $request->header($prefix.'-timestamp');
            $signature = $request->header($prefix.'-signature');

            if (is_string($id) && $id !== '' && is_string($timestamp) && $timestamp !== '' && is_string($signature) && $signature !== '') {
                return [$id, $timestamp, $signature];
            }
        }

        return null;
    }
}
