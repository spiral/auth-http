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
use Spiral\Auth\Exception\AuthException;
use Spiral\Auth\HttpTransportInterface;
use Spiral\Auth\Middleware\AuthMiddleware;
use Spiral\Auth\Middleware\Firewall\AbstractFirewall;
use Spiral\Auth\Middleware\Firewall\ExceptionFirewall;
use Spiral\Auth\Middleware\Firewall\OverwriteFirewall;
use Spiral\Auth\TransportRegistry;
use Spiral\Core\Container;
use Spiral\Http\Config\HttpConfig;
use Spiral\Http\Http;
use Spiral\Http\Pipeline;
use Spiral\Tests\Auth\Diactoros\ResponseFactory;
use Zend\Diactoros\ServerRequest;
use Zend\Diactoros\Uri;

class FirewallTest extends TestCase
{
    private $container;

    public function setUp(): void
    {
        $this->container = new Container();
    }

    public function testExceptionOK(): void
    {
        $http = $this->getCore(
            new ExceptionFirewall(new AuthException()),
            new \Spiral\Auth\Transport\HeaderTransport()
        );

        $http->setHandler(function (ServerRequestInterface $request, ResponseInterface $response): void {
            echo 'OK';
        });

        $response = $http->handle(new ServerRequest([], [], null, 'GET', 'php://input', [
            'X-Auth-Token' => 'ok'
        ]));

        $this->assertSame('OK', (string)$response->getBody());
    }

    public function testNoActorException(): void
    {
        $http = $this->getCore(
            new ExceptionFirewall(new AuthException('no user')),
            new \Spiral\Auth\Transport\HeaderTransport()
        );

        $http->setHandler(function (ServerRequestInterface $request, ResponseInterface $response): void {
            echo 'OK';
        });

        $this->expectException(AuthException::class);
        $response = $http->handle(new ServerRequest([], [], null, 'GET', 'php://input', [
            'X-Auth-Token' => 'no-actor'
        ]));

        $this->assertSame('OK', (string)$response->getBody());
    }

    public function testBadTokenException(): void
    {
        $http = $this->getCore(
            new ExceptionFirewall(new AuthException('no user')),
            new \Spiral\Auth\Transport\HeaderTransport()
        );

        $http->setHandler(function (ServerRequestInterface $request, ResponseInterface $response): void {
            echo 'OK';
        });

        $this->expectException(AuthException::class);
        $response = $http->handle(new ServerRequest([], [], null, 'GET', 'php://input', [
            'X-Auth-Token' => 'bad'
        ]));

        $this->assertSame('OK', (string)$response->getBody());
    }

    public function testOverwriteOK(): void
    {
        $http = $this->getCore(
            new OverwriteFirewall(new Uri('/login')),
            new \Spiral\Auth\Transport\HeaderTransport()
        );

        $http->setHandler(function (ServerRequestInterface $request, ResponseInterface $response): void {
            echo $request->getUri();
        });

        $response = $http->handle(new ServerRequest([], [], new Uri('/admin'), 'GET', 'php://input', [
            'X-Auth-Token' => 'ok'
        ]));

        $this->assertSame('/admin', (string)$response->getBody());
    }

    public function testNoActorOverwrite(): void
    {
        $http = $this->getCore(
            new OverwriteFirewall(new Uri('/login')),
            new \Spiral\Auth\Transport\HeaderTransport()
        );

        $http->setHandler(function (ServerRequestInterface $request, ResponseInterface $response): void {
            echo $request->getUri();
        });

        $response = $http->handle(new ServerRequest([], [], new Uri('/admin'), 'GET', 'php://input', [
            'X-Auth-Token' => 'no-actor'
        ]));

        $this->assertSame('/login', (string)$response->getBody());
    }

    public function testBadTokenOverwrite(): void
    {
        $http = $this->getCore(
            new OverwriteFirewall(new Uri('/login')),
            new \Spiral\Auth\Transport\HeaderTransport()
        );

        $http->setHandler(function (ServerRequestInterface $request, ResponseInterface $response): void {
            echo $request->getUri();
        });

        $response = $http->handle(new ServerRequest([], [], new Uri('/admin'), 'GET', 'php://input', [
            'X-Auth-Token' => 'bad'
        ]));

        $this->assertSame('/login', (string)$response->getBody());
    }

    protected function getCore(AbstractFirewall $firewall, HttpTransportInterface $transport): Http
    {
        $config = new HttpConfig([
            'basePath'   => '/',
            'headers'    => [
                'Content-Type' => 'text/html; charset=UTF-8'
            ],
            'middleware' => [],
        ]);

        $http = new Http(
            $config,
            new Pipeline($this->container),
            new ResponseFactory($config),
            $this->container
        );

        $http->getPipeline()->pushMiddleware(
            new AuthMiddleware(
                $this->container,
                new TestProvider(),
                new TestStorage(),
                $reg = new TransportRegistry()
            )
        );
        $http->getPipeline()->pushMiddleware($firewall);

        $reg->setTransport('transport', $transport);

        return $http;
    }
}
