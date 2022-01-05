<?php
declare(strict_types=1);
namespace ReaZzon\JWTAuth\Http\Middlewares;

use ReaZzon\JWTAuth\Classes\Guards\JWTGuard;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\UserNotDefinedException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;

use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Class ResolveUser
 * @package ReaZzon\JWTAuth\Http\Middlewares
 */
class ResolveBackendUser
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return mixed
     */
    public function handle($request, \Closure $next)
    {
        try {
            /** @var JWTGuard $obJWTGuard */
            $obJWTGuard = app('JWTGuard');

            if (!$obJWTGuard->hasToken()) {
                abort('406', 'Token not provided');
            }

            $obJWTGuard->userOrFail();

            // validation for backend user
            $obJWTGuard->validateBackendUser();

            return $next($request);
        } catch (TokenExpiredException|UserNotDefinedException $e) {
            abort(406, 'Token is expired');
        } catch (TokenBlacklistedException $e) {
            abort(406, 'Token is blacklisted');
        } catch (JWTException $e) {
            abort(406, 'Token not found in request');
        }
    }
}
