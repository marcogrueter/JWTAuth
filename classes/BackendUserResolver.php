<?php
declare(strict_types=1);

namespace ReaZzon\JWTAuth\Classes;

use October\Rain\Auth\Manager as AuthManager;
use October\Rain\Support\Traits\Singleton;
use ReaZzon\JWTAuth\Classes\Contracts\Plugin;
use ReaZzon\JWTAuth\Classes\Contracts\UserPluginResolver as UserPluginResolverContract;
use Tymon\JWTAuth\Contracts\JWTSubject;

/**
 *
 */
final class BackendUserResolver implements UserPluginResolverContract
{
    use Singleton;

    private array $plugin;

    /**
     * Boot resolver
     *
     * @return void
     * @throws \SystemException
     */
    public function init(): void
    {

    }

    /**
     * @return string
     */
    public function getModel(): string
    {
        return \Backend\Models\User::class;
    }

    /**
     * @param $model
     * @return JWTSubject
     */
    public function resolveModel($model): JWTSubject
    {
        return $this->getResolver()->resolve($model);
    }

    public function getResolver(): Plugin
    {
        return app(\ReaZzon\JWTAuth\Classes\Resolvers\RainlabBackend::class);
    }

    /**
     * @return AuthManager
     */
    public function getProvider(): AuthManager
    {
        return app('backend.auth');
    }

    public function getSupportPlugins(): array
    {
        return [];
    }
}
