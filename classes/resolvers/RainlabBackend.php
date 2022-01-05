<?php
declare(strict_types=1);

namespace ReaZzon\JWTAuth\Classes\Resolvers;

use Backend\Models\User as BackendUserModel;
use ReaZzon\JWTAuth\Classes\Contracts\Plugin;
use ReaZzon\JWTAuth\Classes\Exception\PluginModelResolverException;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Model;

/**
 *
 */
final class RainlabBackend implements Plugin
{
    /**
     * @param Model $model
     * @return JWTSubject
     * @throws PluginModelResolverException
     */
    public function resolve(Model $model): JWTSubject
    {
        if (!$model instanceof BackendUserModel) {
            throw new PluginModelResolverException;
        }

        if (!$model->hasPermission('reazzon.jwtauth.allow_jwt_login')) {
            throw new AccessDeniedHttpException('JWT auth not allowed');
        }

        $proxyObject = $this->proxyObject();
        return (new $proxyObject)->setRawAttributes($model->getAttributes());
    }

    /**
     * @return BackendUserModel|JWTSubject
     */
    private function proxyObject()
    {
        return new class extends BackendUserModel implements JWTSubject {
            public $exists = true;

            public function getJWTIdentifier()
            {
                return $this->extendableCall('getJWTIdentifier', []);
            }

            public function getJWTCustomClaims()
            {
                return $this->extendableCall('getJWTCustomClaims', []);
            }

            public function afterRegistrationActivate()
            {
                return 'on';
            }
        };
    }

    public function initActivation($model): string
    {
        // TODO: Implement initActivation() method.
    }

    public function activateByCode($code)
    {
        // TODO: Implement activateByCode() method.
    }
}
