<?php

declare(strict_types=1);

namespace Koamishin\Auth\Facades;

use Illuminate\Support\Facades\Facade;
use Koamishin\Auth\KoamishinAuth;

/**
 * @method static string getLoginUrl(?string $returnTo = null)
 * @method static \Koamishin\Auth\KoamishinUser handleCallback(string $code, string $state)
 * @method static \Koamishin\Auth\KoamishinUser|null user()
 * @method static bool check()
 * @method static void logout()
 *
 * @see KoamishinAuth
 */
class Koamishin extends Facade
{
    #[\Override]
    protected static function getFacadeAccessor(): string
    {
        return KoamishinAuth::class;
    }
}
