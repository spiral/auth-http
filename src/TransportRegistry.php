<?php
/**
 * Spiral Framework.
 *
 * @license   MIT
 * @author    Anton Titov (Wolfy-J)
 */
declare(strict_types=1);

namespace Spiral\Auth;

use Spiral\Auth\Exception\TransportException;

/**
 * Manages list of transports by their names, manages token storage association.
 */
final class TransportRegistry
{
    /** @var HttpTransportInterface[] */
    private $transports = [];

    /**
     * @param string                 $name
     * @param HttpTransportInterface $transport
     */
    public function setTransport(string $name, HttpTransportInterface $transport)
    {
        $this->transports[$name] = $transport;
    }

    /**
     * @param string $name
     * @return HttpTransportInterface
     */
    public function getTransport(string $name): HttpTransportInterface
    {
        if (!isset($this->transports[$name])) {
            throw new TransportException("Undefined auth transport {$name}");
        }

        return $this->transports[$name];
    }

    /**
     * @return HttpTransportInterface[]
     */
    public function getTransports(): array
    {
        return $this->transports;
    }
}