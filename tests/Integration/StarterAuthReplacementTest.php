<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Koamishin\Auth\Http\Controllers\AuthenticationController;
use Tests\TestCase;

class StarterAuthReplacementTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (getenv('KOAMISHIN_STARTER_REPLACEMENT_TEST') !== '1') {
            $this->markTestSkipped('This test runs in the Composer-installed starter-kit consumer matrix.');
        }
    }

    public function test_replaced_starter_routes_use_the_sdk_controller_and_remove_local_credential_posts(): void
    {
        $routes = Route::getRoutes();

        $this->assertSame(AuthenticationController::class.'@login', $routes->getByName('login')?->getActionName());
        $this->assertSame(AuthenticationController::class.'@register', $routes->getByName('register')?->getActionName());
        $this->assertSame(AuthenticationController::class.'@logout', $routes->getByName('logout')?->getActionName());
        $this->assertNull($routes->getByName('password.email'));
        $this->assertNull($routes->getByName('password.store'));
        $this->assertNull($routes->getByName('verification.notice'));
        $this->assertNull($routes->getByName('password.confirm'));

        $this->post('/login')->assertMethodNotAllowed();
        $this->post('/register')->assertMethodNotAllowed();
    }
}
