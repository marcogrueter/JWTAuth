<?php namespace ReaZzon\JWTAuth\Classes\Guards;

use Illuminate\Contracts\Auth\Authenticatable;
use October\Rain\Auth\Models\User;
use ReaZzon\JWTAuth\Classes\Contracts\UserPluginResolver;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\JWTGuard as JWTGuardBase;
use ReaZzon\JWTAuth\Classes\Behaviors\UserSubjectBehavior;

use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;


/**
 * Class JWTGuard
 * @package ReaZzon\JwtUser\Classes\Guards
 */
class JWTGuard extends JWTGuardBase
{
    /**
     * @param Authenticatable $user
     * @return string
     */
    public function login($user): string
    {
        $this->validateMethodParam($user);

        $userPluginResolver = app(UserPluginResolver::class);
        $token = $this->jwt->fromSubject($userPluginResolver->resolveModel($user));
        $this->setToken($token)->setUser($user);

        return $token;
    }

    /**
     * @param User $user
     */
    private function validateMethodParam(Authenticatable $user): void
    {
        if (!$user->isClassExtendedWith(UserSubjectBehavior::class)) {
            throw new \InvalidArgumentException(
                sprintf('user param must extend %s', UserSubjectBehavior::class)
            );
        }
    }

    /**
     * @return bool
     */
    public function hasToken(): bool
    {
        return $this->jwt->parser()->setRequest($this->getRequest())->hasToken();
    }

    public function validateBackendUser()
    {
        $user = $this->user();

        if ($this->isBackendUserModel($user)) {
            if (!$user->hasPermission('reazzon.jwtauth.allow_jwt_login')) {
                throw new AccessDeniedHttpException('JWT auth not allowed');
            }
        }
    }

    private function isBackendUserModel(Authenticatable $user)
    {
        return $user instanceof \Backend\Models\User;
    }
}
