<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Koamishin\Auth\KoamishinWebhookProcessor;
use Koamishin\Auth\KoamishinWebhookValidator;
use Tests\TestCase;

require_once __DIR__.'/Support/bootstrap.php';

class KoamishinWebhookTest extends TestCase
{
    public function test_empty_secret_is_rejected_even_with_a_matching_signature(): void
    {
        $timestamp = (string) time();
        $body = '{}';
        $signature = 'v1,'.base64_encode(hash_hmac('sha256', "msg_123.{$timestamp}.{$body}", '', true));
        $request = $this->webhook($timestamp, $body, $signature);

        $this->assertFalse(KoamishinWebhookValidator::isValid($request, ''));
    }

    public function test_legacy_and_standard_signature_formats_are_explicit(): void
    {
        $body = '{"type":"user.created"}';
        $legacy = $this->webhook('1700000000', $body, 'v1,t0D4O9jNspxA7H8Gtk+BQFLLcwq3QEaVaYFt5vZwkaI=');
        $standard = $this->webhook('1700000000', $body, 'v1,wrong v1,GerP7hCLZNpaU7JkjQJzgOgGCE7HWl8bXq29V0mI0LU=');
        $secret = 'whsec_c3RhbmRhcmRzZWNyZXRrZXk=';

        $this->assertTrue(KoamishinWebhookValidator::isValid($legacy, 'secret123', PHP_INT_MAX, 'legacy'));
        $this->assertTrue(KoamishinWebhookValidator::isValid($standard, $secret, PHP_INT_MAX, 'standard'));
        $this->assertFalse(KoamishinWebhookValidator::isValid($standard, $secret, PHP_INT_MAX, 'legacy'));
        $this->assertFalse(KoamishinWebhookValidator::isValid($standard, 'whsec_invalid!', PHP_INT_MAX, 'standard'));
        $this->assertFalse(KoamishinWebhookValidator::isValid($standard, $secret, PHP_INT_MAX, 'unknown'));
    }

    public function test_invalid_or_expired_timestamps_are_rejected(): void
    {
        $invalid = $this->webhook('1e10', '{}', 'v1,invalid');
        $expired = $this->webhook('1700000000', '{}', 'v1,invalid');

        $this->assertFalse(KoamishinWebhookValidator::isValid($invalid, 'secret123'));
        $this->assertFalse(KoamishinWebhookValidator::isValid($expired, 'secret123', 1));
    }

    public function test_standard_headers_are_verified_without_svix_aliases(): void
    {
        $timestamp = (string) time();
        $key = 'standardsecretkey';
        $secret = 'whsec_'.base64_encode($key);
        $signature = 'v1,'.base64_encode(hash_hmac('sha256', "msg_standard.{$timestamp}.{}", $key, true));
        $request = Request::create('/webhook', 'POST', server: [
            'HTTP_WEBHOOK_ID' => 'msg_standard',
            'HTTP_WEBHOOK_TIMESTAMP' => $timestamp,
            'HTTP_WEBHOOK_SIGNATURE' => $signature,
        ], content: '{}');

        $this->assertTrue(KoamishinWebhookValidator::isValid($request, $secret, format: 'standard'));
        $this->assertSame('msg_standard', KoamishinWebhookValidator::verifiedDeliveryId($request, $secret, format: 'standard'));
        $this->assertFalse(KoamishinWebhookValidator::isValid($request, $secret, format: 'legacy'));
    }

    public function test_standard_header_names_are_not_mixed_with_svix_aliases(): void
    {
        $timestamp = (string) time();
        $key = 'standardsecretkey';
        $secret = 'whsec_'.base64_encode($key);
        $signature = 'v1,'.base64_encode(hash_hmac('sha256', "msg_mixed.{$timestamp}.{}", $key, true));
        $request = Request::create('/webhook', 'POST', server: [
            'HTTP_WEBHOOK_ID' => 'msg_mixed',
            'HTTP_SVIX_TIMESTAMP' => $timestamp,
            'HTTP_SVIX_SIGNATURE' => $signature,
        ], content: '{}');

        $this->assertFalse(KoamishinWebhookValidator::isValid($request, $secret, format: 'standard'));
    }

    public function test_invalid_complete_standard_headers_do_not_fall_back_to_svix_aliases(): void
    {
        $timestamp = (string) time();
        $key = 'standardsecretkey';
        $secret = 'whsec_'.base64_encode($key);
        $signature = 'v1,'.base64_encode(hash_hmac('sha256', "msg_svix.{$timestamp}.{}", $key, true));
        $request = Request::create('/webhook', 'POST', server: [
            'HTTP_WEBHOOK_ID' => 'msg_standard',
            'HTTP_WEBHOOK_TIMESTAMP' => $timestamp,
            'HTTP_WEBHOOK_SIGNATURE' => 'v1,invalid',
            'HTTP_SVIX_ID' => 'msg_svix',
            'HTTP_SVIX_TIMESTAMP' => $timestamp,
            'HTTP_SVIX_SIGNATURE' => $signature,
        ], content: '{}');

        $this->assertFalse(KoamishinWebhookValidator::isValid($request, $secret, format: 'standard'));
    }

    public function test_replay_processing_uses_the_verified_standard_id_when_aliases_differ(): void
    {
        Cache::store('array')->flush();
        $timestamp = (string) time();
        $key = 'standardsecretkey';
        $secret = 'whsec_'.base64_encode($key);
        $standardSignature = 'v1,'.base64_encode(hash_hmac('sha256', "msg_standard.{$timestamp}.{}", $key, true));
        $request = function (string $aliasId) use ($timestamp, $key, $standardSignature): Request {
            return Request::create('/webhook', 'POST', server: [
                'HTTP_WEBHOOK_ID' => 'msg_standard',
                'HTTP_WEBHOOK_TIMESTAMP' => $timestamp,
                'HTTP_WEBHOOK_SIGNATURE' => $standardSignature,
                'HTTP_SVIX_ID' => $aliasId,
                'HTTP_SVIX_TIMESTAMP' => $timestamp,
                'HTTP_SVIX_SIGNATURE' => 'v1,'.base64_encode(hash_hmac('sha256', "{$aliasId}.{$timestamp}.{}", $key, true)),
            ], content: '{}');
        };
        $count = 0;
        $handler = function () use (&$count): void {
            $count++;
        };

        $this->assertTrue(KoamishinWebhookProcessor::processOnce($request('msg_first_alias'), $secret, $handler, format: 'standard', cacheStore: 'array'));
        $this->assertFalse(KoamishinWebhookProcessor::processOnce($request('msg_second_alias'), $secret, $handler, format: 'standard', cacheStore: 'array'));
        $this->assertSame(1, $count);
    }

    public function test_processed_delivery_is_acknowledged_after_success_and_not_processed_twice(): void
    {
        Cache::store('array')->flush();
        $request = $this->currentWebhook('secret123');
        $count = 0;
        $handler = function () use (&$count): void {
            $count++;
        };

        $first = KoamishinWebhookProcessor::processOnce($request, 'secret123', $handler, cacheStore: 'array');
        $second = KoamishinWebhookProcessor::processOnce($request, 'secret123', $handler, cacheStore: 'array');

        $this->assertTrue($first);
        $this->assertFalse($second);
        $this->assertSame(1, $count);
    }

    public function test_failed_handler_does_not_acknowledge_a_delivery(): void
    {
        Cache::store('array')->flush();
        $request = $this->currentWebhook('secret123');

        try {
            KoamishinWebhookProcessor::processOnce($request, 'secret123', fn () => throw new RuntimeException('failed'), cacheStore: 'array');
            $this->fail('The handler failure was not propagated.');
        } catch (RuntimeException $exception) {
            $this->assertSame('failed', $exception->getMessage());
        }

        $this->assertTrue(KoamishinWebhookProcessor::processOnce($request, 'secret123', fn () => null, cacheStore: 'array'));
    }

    public function test_replay_retention_must_cover_the_full_future_and_past_timestamp_window(): void
    {
        $request = $this->currentWebhook('secret123');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid webhook replay configuration.');

        KoamishinWebhookProcessor::processOnce($request, 'secret123', fn () => null, tolerance: 300, cacheStore: 'array', retentionSeconds: 599);
    }

    private function currentWebhook(string $secret): Request
    {
        $timestamp = (string) time();
        $body = '{}';
        $signature = 'v1,'.base64_encode(hash_hmac('sha256', "msg_123.{$timestamp}.{$body}", $secret, true));

        return $this->webhook($timestamp, $body, $signature);
    }

    private function webhook(string $timestamp, string $body, string $signature): Request
    {
        return Request::create('/webhook', 'POST', server: [
            'HTTP_SVIX_ID' => 'msg_123',
            'HTTP_SVIX_TIMESTAMP' => $timestamp,
            'HTTP_SVIX_SIGNATURE' => $signature,
        ], content: $body);
    }
}
