<?php

declare(strict_types=1);

use Tests\TestCase;

class LegacyInterceptionTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (getenv('KOAMISHIN_LEGACY_CONSUMER_TEST') !== '1') {
            $this->markTestSkipped('This test runs in the Composer-installed consumer matrix.');
        }
    }

    public function test_credentials_added_after_setup_keep_legacy_hosted_interception(): void
    {
        $this->assertTrue($this->app->configurationIsCached());
        $this->assertTrue($this->app->routesAreCached());
        $this->assertFalse(config('koamishin-setup.migrate_hosted_routes'));
        $response = $this->get('/login')->assertRedirect();
        $this->assertStringStartsWith('https://portal.test/oauth/authorize?', $response->headers->get('Location'));
    }
}
