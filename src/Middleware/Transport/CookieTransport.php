<?php
/**
 * Spiral Framework.
 *
 * @license   MIT
 * @author    Anton Titov (Wolfy-J)
 */
declare(strict_types=1);

namespace Spiral\Auth\Middleware\Transport;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Spiral\Auth\HttpTransportInterface;
use Spiral\Cookies\Cookie;
use Spiral\Cookies\CookieQueue;

/**
 * Stores auth tokens in cookies.
 */
final class CookieTransport implements HttpTransportInterface
{
    /** @var string */
    private $cookie;

    /**
     * @param string $cookie
     */
    public function __construct(string $cookie)
    {
        $this->cookie = $cookie;
    }

    /**
     * @inheritDoc
     */
    public function fetchToken(Request $request): ?string
    {
        $cookies = $request->getCookieParams();
        if (isset($cookies[$this->cookie])) {
            return $cookies[$this->cookie];
        }

        return null;
    }

    /**
     * @inheritDoc
     */
    public function commitToken(
        Request $request,
        Response $response,
        string $tokenID = null,
        \DateTimeInterface $expiresAt = null
    ): Response {
        /** @var CookieQueue $cookieQueue */
        $cookieQueue = $request->getAttribute(CookieQueue::ATTRIBUTE);
        if ($cookieQueue === null) {

            return $response->withAddedHeader(
                'Set-Cookie',
                Cookie::create($this->cookie, $tokenID, $this->getLifetime($expiresAt))->createHeader()
            );
        }

        if ($tokenID === null) {
            $cookieQueue->delete($this->cookie);
        } else {
            $cookieQueue->set($this->cookie, $tokenID, $this->getLifetime($expiresAt));
        }

        return $response;
    }

    /**
     * @inheritDoc
     */
    public function removeToken(Request $request, Response $response, string $tokenID): Response
    {
        // reset to null
        return $this->commitToken($request, $response, null, null);
    }

    /**
     * @param \DateTimeInterface|null $expiresAt
     * @return int|null
     */
    private function getLifetime(\DateTimeInterface $expiresAt = null): ?int
    {
        if ($expiresAt === null) {
            return null;
        }

        return max($expiresAt->getTimestamp() - time(), 0);
    }
}