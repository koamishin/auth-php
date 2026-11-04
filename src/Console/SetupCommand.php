<?php

declare(strict_types=1);

namespace Koamishin\Auth\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Request;
use Koamishin\Auth\Http\Controllers\AuthenticationController;
use Koamishin\Auth\Middleware\AuthenticateKoamishin;

class SetupCommand extends Command
{
    protected $signature = 'koamishin:setup {--migrate-hosted-routes : Disable active legacy login and registration interception}';

    protected $description = 'Enable the dedicated Koamishin authentication routes and guard';

    private const LEGACY_CONFIG = <<<'PHP'
<?php

return [
    'enabled' => true,
];
PHP;

    private static function marker(bool $migrateHostedRoutes): string
    {
        $value = $migrateHostedRoutes ? 'true' : 'false';

        return "<?php\n\nreturn [\n    'enabled' => true,\n    'migrate_hosted_routes' => {$value},\n];\n";
    }

    public function handle(): int
    {
        if ($this->laravel->configurationIsCached() || $this->laravel->routesAreCached()) {
            $this->error('Clear the configuration and route caches before setup, then rebuild them after setup.');

            return self::FAILURE;
        }

        $path = config_path('koamishin-setup.php');
        $markerExists = file_exists($path);
        $existingContents = $markerExists && is_file($path) ? @file_get_contents($path) : false;
        $normalizedContents = is_string($existingContents) ? str_replace("\r\n", "\n", $existingContents) : null;
        if ($markerExists && (is_link($path) || ! in_array($normalizedContents, [self::LEGACY_CONFIG."\n", self::marker(false), self::marker(true)], true))) {
            $this->error('config/koamishin-setup.php already exists and is not an unmodified setup file. No files were changed.');

            return self::FAILURE;
        }

        $migrateHostedRoutes = $normalizedContents === self::marker(true) || $this->option('migrate-hosted-routes');

        $guard = config('auth.guards.koamishin');
        if ($guard !== null && (! is_array($guard) || ($guard['driver'] ?? null) !== 'koamishin')) {
            $this->error('The existing koamishin guard uses another driver. Resolve the conflict before setup.');

            return self::FAILURE;
        }

        $this->laravel->make(Kernel::class);
        $alias = $this->laravel['router']->getMiddleware()['koamishin.auth'] ?? null;
        if ($alias !== null && $alias !== AuthenticateKoamishin::class) {
            $this->error('The koamishin.auth middleware alias is already in use. Resolve the conflict before setup.');

            return self::FAILURE;
        }

        foreach (['login' => 'GET', 'register' => 'GET', 'callback' => 'GET', 'logout' => 'POST'] as $action => $method) {
            $methods = $method === 'GET' ? ['GET', 'HEAD'] : [$method];
            foreach ($this->laravel['router']->getRoutes() as $route) {
                if ($route->isFallback && $route->getName() !== 'koamishin.'.$action) {
                    continue;
                }

                $ours = $markerExists
                    && config('koamishin-setup.enabled') === true
                    && $route->getActionName() === AuthenticationController::class.'@'.$action
                    && $route->getName() === 'koamishin.'.$action
                    && $route->uri() === 'koamishin/'.$action
                    && $route->methods() === $methods
                    && $route->getDomain() === null
                    && $route->gatherMiddleware() === ['web'];
                $samePath = $route->uri() === 'koamishin/'.$action
                    && array_intersect($methods, $route->methods()) !== [];
                $matches = false;
                foreach ($methods as $requestMethod) {
                    $request = Request::create('/koamishin/'.$action, $requestMethod);
                    $route->matches($request);
                    if (in_array($requestMethod, $route->methods(), true)
                        && preg_match($route->getCompiled()->getRegex(), $request->getPathInfo()) === 1) {
                        $matches = true;
                        break;
                    }
                }
                if (! $ours && ($route->getName() === 'koamishin.'.$action || $samePath || $matches)) {
                    $this->error("Route conflict for {$method} /koamishin/{$action} or koamishin.{$action}. No files were changed.");

                    return self::FAILURE;
                }
            }
        }

        if (! $markerExists) {
            $file = @fopen($path, 'x');
            if ($file === false) {
                $this->error('Unable to create config/koamishin-setup.php; no existing file was overwritten.');

                return self::FAILURE;
            }

            $contents = self::marker($migrateHostedRoutes);
            $written = fwrite($file, $contents);
            fclose($file);
            if ($written !== strlen($contents)) {
                $this->error('Unable to write the complete setup file. Remove the incomplete file before retrying.');

                return self::FAILURE;
            }
        } elseif ($this->option('migrate-hosted-routes') && $normalizedContents !== self::marker(true)) {
            $this->error('The existing setup file was not changed. Review and remove config/koamishin-setup.php, then rerun setup with --migrate-hosted-routes.');

            return self::FAILURE;
        }

        $this->info('Koamishin setup enabled. Existing application files were not replaced.');
        $this->line('The guard and routes are available on the next application boot.');
        $this->line('Protect browser routes with the koamishin.auth middleware.');
        if ($migrateHostedRoutes) {
            $this->warn('The SDK legacy interception of /login and /register will be disabled on the next application boot.');
        } else {
            $this->line('Legacy hosted interception remains unchanged; use --migrate-hosted-routes to opt out across deployments.');
        }
        $this->line('Configure KOAMISHIN_PORTAL_URL, KOAMISHIN_PUBLISHABLE_KEY, KOAMISHIN_SECRET_KEY, KOAMISHIN_APPLICATION_ID and KOAMISHIN_REDIRECT_URI in your environment.');
        $this->line('Register the exact callback URL ending in /koamishin/callback in the Portal. See the SDK README for legacy credentials and deployment instructions.');

        return self::SUCCESS;
    }

}
