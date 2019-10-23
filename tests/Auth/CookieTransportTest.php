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
use Spiral\Auth\HttpTransportInterface;
use Spiral\Auth\Middleware\AuthMiddleware;
use Spiral\Auth\TransportRegistry;
use Spiral\Core\Container;
use Spiral\Http\Config\HttpConfig;
use Spiral\Http\Http;
use Spiral\Http\Pipeline;
use Spiral\Tests\Auth\Diactoros\ResponseFactory;
use Zend\Diactoros\ServerRequest;

class  CookieTransportTest extends TestCase
{
    private $container;

    public function setUp()
    {
        $this->container = new Container();

    }

    public function testCookieToken()
    {
        $http = $this->getCore(new \Spiral\Auth\Middleware\Transport\CookieTransport('auth-token'));

        $http->setHandler(function (ServerRequestInterface $request, ResponseInterface $response) {
            if ($request->getAttribute('auth-context')->getToken() === null) {
                echo 'no token';
            } else {
                echo $request->getAttribute('auth-context')->getToken()->getID();
                echo ':';
                echo json_encode($request->getAttribute('auth-context')->getToken()->getPayload());
            }
        });

        $response = $http->handle(new ServerRequest([], [], null, 'GET', 'php://input', [], [
            'auth-token' => 'good-token'
        ]));

        $this->assertSame(['text/html; charset=UTF-8'], $response->getHeader('Content-Type'));
        $this->assertSame('good-token:{"id":"good-token"}', (string)$response->getBody());
    }

    public function testBadCookieToken()
    {
        $http = $this->getCore(new \Spiral\Auth\Middleware\Transport\CookieTransport('auth-token'));

        $http->setHandler(function (ServerRequestInterface $request, ResponseInterface $response) {
            if ($request->getAttribute('auth-context')->getToken() === null) {
                echo 'no token';
            } else {
                echo $request->getAttribute('auth-context')->getToken()->getID();
                echo ':';
                echo json_encode($request->getAttribute('auth-context')->getToken()->getPayload());
            }
        });

        $response = $http->handle(new ServerRequest([], [], null, 'GET', 'php://input', [], [
            'auth-token' => 'bad'
        ]));

        $this->assertSame(['text/html; charset=UTF-8'], $response->getHeader('Content-Type'));
        $this->assertSame('no token', (string)$response->getBody());
    }

    protected function getCore(HttpTransportInterface $transport): Http
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
        $reg->setTransport('transport', $transport);

        return $http;
    }
}