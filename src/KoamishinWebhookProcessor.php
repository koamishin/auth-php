<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use InvalidArgumentException;
use RuntimeException;

class KoamishinWebhookProcessor
{
    /**
     * Process a verified delivery once per cache namespace and acknowledge it only
     * after the handler succeeds. The handler must still be idempotent.
     */
    public static function processOnce(
        Request $request,
        string $secret,
        callable $handler,
        int $tolerance = 300,
        string $format = 'legacy',
        ?string $cacheStore = null,
        string $namespace = 'default',
        int $retentionSeconds = 86400,
        int $lockSeconds = 60,
    ): bool {
        $id = KoamishinWebhookValidator::verifiedDeliveryId($request, $secret, $tolerance, $format);
        if ($id === null) {
            throw new InvalidArgumentException('Invalid webhook signature.');
        }
        if ($namespace === '' || $tolerance > intdiv(PHP_INT_MAX, 2) || $retentionSeconds < max($tolerance * 2, 1) || $lockSeconds < 1) {
            throw new InvalidArgumentException('Invalid webhook replay configuration.');
        }

        $cache = Cache::store($cacheStore);
        if (! $cache->getStore() instanceof LockProvider) {
            throw new RuntimeException('Webhook replay storage must support atomic locks.');
        }

        $identity = hash('sha256', $namespace."\0".$id);
        $lock = $cache->lock('koamishin:webhook:lock:'.$identity, $lockSeconds);
        if (! $lock->get()) {
            throw new RuntimeException('Webhook delivery is already being processed.');
        }

        try {
            $processedKey = 'koamishin:webhook:processed:'.$identity;
            if ($cache->has($processedKey)) {
                return false;
            }

            $handler($request);
            if (! $cache->put($processedKey, true, $retentionSeconds)) {
                throw new RuntimeException('Could not record the processed webhook.');
            }

            return true;
        } finally {
            $lock->release();
        }
    }
}
