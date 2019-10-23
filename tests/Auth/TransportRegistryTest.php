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
use Spiral\Auth\Exception\TransportException;
use Spiral\Auth\Middleware\Transport\CookieTransport;
use Spiral\Auth\TransportRegistry;

class TransportRegistryTest extends TestCase
{
    public function testGetTransports()
    {
        $t = new TransportRegistry();
        $t->setTransport('cookie', new CookieTransport('auth-token'));

        $this->assertCount(1, $t->getTransports());
        $this->assertInstanceOf(CookieTransport::class, $t->getTransport('cookie'));
    }

    public function testGetException()
    {
        $t = new TransportRegistry();

        $this->expectException(TransportException::class);
        $t->getTransport('cookie');
    }
}