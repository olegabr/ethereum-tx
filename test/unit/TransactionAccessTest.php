<?php

namespace Test\Unit;

use InvalidArgumentException;
use RuntimeException;
use Test\TestCase;
use Web3p\EthereumTx\Transaction;
use Web3p\EthereumUtil\Util;

/**
 * Transaction with a setter, so the magic __set setter dispatch can be tested.
 */
class TransactionWithSetter extends Transaction
{
    public $setterCalled = null;

    public function setSomething($value)
    {
        $this->setterCalled = $value;
    }
}

class TransactionAccessTest extends TestCase
{
    /**
     * Return a transaction with the EIP-155 test vector filled in.
     *
     * @return Transaction
     */
    protected function tx(): Transaction
    {
        return new Transaction([
            'nonce' => '0x00',
            'gasPrice' => '0x04a817c800',
            'gas' => '0x5208',
            'to' => '0x3535353535353535353535353535353535353535',
            'value' => '0x0de0b6b3a7640000',
            'data' => '',
            'chainId' => 1,
        ]);
    }

    /**
     * testMagicGetUsesGetter
     *
     * @return void
     */
    public function testMagicGetUsesGetter()
    {
        $util = new Util;
        $privateKey = '4646464646464646464646464646464646464646464646464646464646464646';
        $expected = '0x' . substr($util->sha3(substr(hex2bin(substr($util->privateKeyToPublicKey($privateKey), 2)), 1)), 24);

        $tx = $this->tx();
        $tx->sign('0x' . $privateKey);

        // getTxData() exists, so the magic getter must call it
        $this->assertIsArray($tx->txData);
        $this->assertArrayHasKey(3, $tx->txData);
        // getFromAddress() also exists and is reached through the magic getter
        $this->assertEquals($expected, $tx->fromAddress);
        // an unknown key falls back to the attribute map
        $this->assertNull($tx->signatureThatDoesNotExist);
    }

    /**
     * testMagicSetUsesSetter
     *
     * @return void
     */
    public function testMagicSetUsesSetter()
    {
        $tx = new TransactionWithSetter();
        $tx->something = 'value';

        $this->assertEquals('value', $tx->setterCalled);
    }

    /**
     * testMagicSetUsesOffsetSet
     *
     * @return void
     */
    public function testMagicSetUsesOffsetSet()
    {
        $tx = $this->tx();
        $tx->value = '0x01';

        $this->assertEquals('0x01', $tx['value']);
        $this->assertEquals('0x01', $tx->value);
    }

    /**
     * testOffsetExists
     *
     * @return void
     */
    public function testOffsetExists()
    {
        $tx = $this->tx();

        $this->assertTrue(isset($tx['value']));
        $this->assertTrue(isset($tx->value));
        $this->assertTrue(isset($tx['nonce']));
        $this->assertFalse(isset($tx['v']));
        $this->assertFalse(isset($tx['unknown']));
        $this->assertFalse(isset($tx->unknown));
    }

    /**
     * testOffsetUnset
     *
     * @return void
     */
    public function testOffsetUnset()
    {
        $tx = $this->tx();
        $this->assertTrue(isset($tx['value']));

        unset($tx['value']);
        $this->assertFalse(isset($tx['value']));
        $this->assertNull($tx['value']);

        // unsetting twice and unsetting an unknown key are no-ops
        unset($tx['value']);
        unset($tx['unknown']);
        $this->assertFalse(isset($tx['unknown']));
    }

    /**
     * testMagicUnset
     *
     * @return void
     */
    public function testMagicUnset()
    {
        $tx = $this->tx();
        $this->assertTrue(isset($tx->value));

        unset($tx->value);
        $this->assertFalse(isset($tx->value));
        $this->assertNull($tx->value);
    }

    /**
     * testOffsetSetUnknownKeyIsIgnored
     *
     * @return void
     */    public function testOffsetSetUnknownKeyIsIgnored()
    {
        $tx = $this->tx();
        $before = $tx->getTxData();

        $tx['unknown'] = 'value';

        $this->assertEquals($before, $tx->getTxData());
        $this->assertNull($tx['unknown']);
    }

    /**
     * testLengthLimitHex
     *
     * @return void
     */
    public function testLengthLimitHex()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('to exceeds the length limit.');

        $tx = $this->tx();
        // 21 bytes for a 20 byte field
        $tx['to'] = '0x' . str_repeat('11', 21);
    }

    /**
     * testLengthLimitRaw
     *
     * @return void
     */
    public function testLengthLimitRaw()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('to exceeds the length limit.');

        $tx = $this->tx();
        // not hex, so the limit is compared against the raw string length
        $tx['to'] = str_repeat('z', 21);
    }

    /**
     * testZeroValueIsDropped
     *
     * @return void
     */
    public function testZeroValueIsDropped()
    {
        $tx = $this->tx();
        $tx['value'] = '0x00';

        $this->assertEquals('', $tx['value']);
    }

    /**
     * testToString
     *
     * @return void
     */
    public function testToString()
    {
        $tx = $this->tx();

        $this->assertEquals($tx->hash(false), (string) $tx);
    }

    /**
     * testHashWithSignature
     *
     * @return void
     */
    public function testHashWithSignature()
    {
        $tx = $this->tx();
        $tx->sign('0x4646464646464646464646464646464646464646464646464646464646464646');

        // with the signature in place the hash of the signed tx is the keccak of
        // its serialized form
        $this->assertEquals(
            (new Util)->sha3(hex2bin($tx->serialize())),
            $tx->hash(true)
        );
        $this->assertNotEquals($tx->hash(false), $tx->hash(true));
    }

    /**
     * testGetFromAddressWithoutSignature
     *
     * @return void
     */
    public function testGetFromAddressWithoutSignature()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid signature r and s.');

        $this->tx()->getFromAddress();
    }

    /**
     * testGetFromAddressFromSignature
     *
     * @return void
     */
    public function testGetFromAddressFromSignature()
    {
        $util = new Util;
        $privateKey = '4646464646464646464646464646464646464646464646464646464646464646';
        $expected = '0x' . substr($util->sha3(substr(hex2bin(substr($util->privateKeyToPublicKey($privateKey), 2)), 1)), 24);

        $signed = $this->tx();
        $signed->sign('0x' . $privateKey);
        $this->assertEquals($expected, $signed->getFromAddress());

        // a transaction restored from its serialized form recovers from r/s/v
        $restored = new Transaction('0x' . $signed->serialize());
        $this->assertEquals($expected, $restored->getFromAddress());
    }

    /**
     * testFromAttributeIsReturnedAsIs
     *
     * @return void
     */
    public function testFromAttributeIsReturnedAsIs()
    {
        $tx = $this->tx();
        $tx['from'] = '0x3535353535353535353535353535353535353535';

        $this->assertEquals('0x3535353535353535353535353535353535353535', $tx->getFromAddress());
    }

    /**
     * testGetFromAddressWithHexValues
     *
     * @return void
     */
    public function testGetFromAddressWithHexValues()
    {
        $util = new Util;
        $privateKey = '4646464646464646464646464646464646464646464646464646464646464646';
        $expected = '0x' . substr($util->sha3(substr(hex2bin(substr($util->privateKeyToPublicKey($privateKey), 2)), 1)), 24);

        $signed = $this->tx();
        $signed->sign('0x' . $privateKey);

        // r/s/v and chainId kept as 0x prefixed hex strings, as a restored tx has them
        $restored = new Transaction([
            'nonce' => $signed['nonce'],
            'gasPrice' => $signed['gasPrice'],
            'gas' => $signed['gas'],
            'to' => $signed['to'],
            'value' => $signed['value'],
            'data' => $signed['data'],
            'r' => $signed['r'],
            's' => $signed['s'],
            'v' => '0x' . dechex($signed['v']),
            'chainId' => '0x1',
        ]);

        $this->assertEquals($expected, $restored->getFromAddress());
    }

    /**
     * testGetFromAddressWithLegacySignature
     *
     * @return void
     */
    public function testGetFromAddressWithLegacySignature()
    {
        $util = new Util;
        $privateKey = '4646464646464646464646464646464646464646464646464646464646464646';
        $expected = '0x' . substr($util->sha3(substr(hex2bin(substr($util->privateKeyToPublicKey($privateKey), 2)), 1)), 24);

        // a pre EIP-155 signature carries v = 27 + recoveryParam and no chain id
        $legacy = new Transaction([
            'nonce' => '0x00',
            'gasPrice' => '0x04a817c800',
            'gas' => '0x5208',
            'to' => '0x3535353535353535353535353535353535353535',
            'value' => '0x0de0b6b3a7640000',
            'data' => '',
        ]);
        $signature = (new \Elliptic\EC('secp256k1'))
            ->keyFromPrivate($privateKey, 'hex')
            ->sign($legacy->hash(false), ['canonical' => true]);
        $legacy['r'] = '0x' . $signature->r->toString(16);
        $legacy['s'] = '0x' . $signature->s->toString(16);
        $legacy['v'] = 27 + $signature->recoveryParam;

        $this->assertEquals($expected, $legacy->getFromAddress());
    }

    /**
     * testSignInvalidPrivateKey
     *
     * @return void
     */
    public function testSignInvalidPrivateKey()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Private key should be hex encoded string');

        $this->tx()->sign('not a key');
    }
}
