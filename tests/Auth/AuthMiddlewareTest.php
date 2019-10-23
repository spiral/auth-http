<?php
/**
 * Spiral Framework.
 *
 * @license   MIT
 * @author    Anton Titov (Wolfy-J)
 */
declare(strict_types=1);

namespace Spiral\Tests\Auth;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Spiral\Auth\AuthContext;
use Spiral\Auth\Middleware\AuthMiddleware;
use Spiral\Auth\Middleware\Transport\HeaderTransport;
use Spiral\Auth\TransportRegistry;
use Spiral\Core\Container;
use Spiral\Http\Config\HttpConfig;
use Spiral\Http\Http;
use Spiral\Http\Pipeline;
use Spiral\Tests\Auth\Diactoros\ResponseFactory;
use Zend\Diactoros\ServerRequest;

class AuthMiddlewareTest extends TestCase
{
    private $container;

    public function setUp()
    {
        $this->container = new Container();

    }

    public function testAttributeRead()
    {
        $http = $this->getCore([]);
        $http->getPipeline()->pushMiddleware(
            new AuthMiddleware(
                $this->container,
                new TestProvider(),
                new TestStorage(),
                new TransportRegistry()
            )
        );

        $http->setHandler(function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write(
                get_class($request->getAttribute('auth-context'))
            );
        });

        $response = $http->handle(new ServerRequest());

        $this->assertSame(['text/html; charset=UTF-8'], $response->getHeader('Content-Type'));
        $this->assertSame(AuthContext::class, (string)$response->getBody());
    }

    public function testNoToken()
    {
        $http = $this->getCore([]);
        $http->getPipeline()->pushMiddleware(
            new AuthMiddleware(
                $this->container,
                new TestProvider(),
                new TestStorage(),
                new TransportRegistry()
            )
        );

        $http->setHandler(function (ServerRequestInterface $request, ResponseInterface $response) {
            if ($request->getAttribute('auth-context')->getToken() === null) {
                echo 'no token';
            }
        });

        $response = $http->handle(new ServerRequest());

        $this->assertSame(['text/html; charset=UTF-8'], $response->getHeader('Content-Type'));
        $this->assertSame('no token', (string)$response->getBody());
    }

    public function testHeaderToken()
    {
        $http = $this->getCore([]);
        $http->getPipeline()->pushMiddleware(
            new AuthMiddleware(
                $this->container,
                new TestProvider(),
                new TestStorage(),
                $reg = new TransportRegistry()
            )
        );

        $reg->setTransport('header', new HeaderTransport());

        $http->setHandler(function (ServerRequestInterface $request, ResponseInterface $response) {
            if ($request->getAttribute('auth-context')->getToken() === null) {
                echo 'no token';
            } else {
                echo $request->getAttribute('auth-context')->getToken()->getID();
                echo ':';
                echo json_encode($request->getAttribute('auth-context')->getToken()->getPayload());
            }
        });

        $response = $http->handle(new ServerRequest([], [], null, 'GET', 'php://input', [
            'X-Auth-Token' => 'good-token'
        ]));

        $this->assertSame(['text/html; charset=UTF-8'], $response->getHeader('Content-Type'));
        $this->assertSame('good-token:{"id":"good-token"}', (string)$response->getBody());
    }

    public function testBadHeaderToken()
    {
        $http = $this->getCore([]);
        $http->getPipeline()->pushMiddleware(
            new AuthMiddleware(
                $this->container,
                new TestProvider(),
                new TestStorage(),
                $reg = new TransportRegistry()
            )
        );

        $reg->setTransport('header', new HeaderTransport());

        $http->setHandler(function (ServerRequestInterface $request, ResponseInterface $response) {
            if ($request->getAttribute('auth-context')->getToken() === null) {
                echo 'no token';
            } else {
                echo $request->getAttribute('auth-context')->getToken()->getID();
                echo ':';
                echo json_encode($request->getAttribute('auth-context')->getToken()->getPayload());
            }
        });

        $response = $http->handle(new ServerRequest([], [], null, 'GET', 'php://input', [
            'X-Auth-Token' => 'bad'
        ]));

        $this->assertSame(['text/html; charset=UTF-8'], $response->getHeader('Content-Type'));
        $this->assertSame('no token', (string)$response->getBody());
    }

    protected function getCore(array $middleware = []): Http
    {
        $config = new HttpConfig([
            'basePath'   => '/',
            'headers'    => [
                'Content-Type' => 'text/html; charset=UTF-8'
            ],
            'middleware' => $middleware,
        ]);

        return new Http(
            $config,
            new Pipeline($this->container),
            new ResponseFactory($config),
            $this->container
        );
    }
}