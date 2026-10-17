<?php

namespace Test\Unit;

use InvalidArgumentException;
use RuntimeException;
use Test\TestCase;
use Web3p\EthereumTx\EIP1559Transaction;
use Web3p\EthereumTx\EIP2930Transaction;
use Web3p\EthereumTx\TypeTransaction;
use Web3p\EthereumUtil\Util;

/**
 * TypeTransaction with an array field that is length checked and zero trimmed,
 * so those guards in offsetSet() are reachable.
 */
class TypeTransactionWithCheckedArray extends TypeTransaction
{
    protected $attributeMap = [
        'list' => [
            'key' => 0,
            'length' => 2,
            'allowZero' => false,
            'allowArray' => true,
        ],
    ];
}

/**
 * TypeTransaction with a setter, so the magic __set setter dispatch is tested.
 */
class TypeTransactionWithSetter extends TypeTransaction
{
    public $setterCalled = null;

    public function setSomething($value)
    {
        $this->setterCalled = $value;
    }
}

class TypeTransactionTest extends TestCase
{    const PK = '0x4646464646464646464646464646464646464646464646464646464646464646';

    /**
     * EIP-1559 transaction data of the spec example.
     *
     * @return array
     */
    protected function tx1559(): array
    {
        return [
            'nonce' => '0x15',
            'to' => '0x3535353535353535353535353535353535353535',
            'gas' => '0x5208',
            'maxPriorityFeePerGas' => '0x4a817c800',
            'maxFeePerGas' => '0x4a817c800',
            'value' => '0x0',
            'chainId' => 4,
            'accessList' => [],
            'data' => '',
        ];
    }

    /**
     * EIP-2930 transaction data of the spec example.
     *
     * @return array
     */
    protected function tx2930(): array
    {
        return [
            'nonce' => '0x15',
            'to' => '0x3535353535353535353535353535353535353535',
            'gas' => '0x5208',
            'gasPrice' => '0x4a817c800',
            'value' => '0x0',
            'chainId' => 4,
            'accessList' => [],
            'data' => '',
        ];
    }

    /**
     * The address of the test private key.
     *
     * @return string
     */
    protected function expectedAddress(): string
    {
        $util = new Util;
        $publicKey = $util->privateKeyToPublicKey(self::PK);

        return '0x' . substr($util->sha3(substr(hex2bin(substr($publicKey, 2)), 1)), 24);
    }

    /**
     * testEIP1559GetFromAddress
     *
     * @return void
     */
    public function testEIP1559GetFromAddress()
    {
        $transaction = new EIP1559Transaction($this->tx1559());
        $transaction->sign(self::PK);

        $this->assertEquals($this->expectedAddress(), $transaction->getFromAddress());
    }

    /**
     * testEIP2930GetFromAddress
     *
     * @return void
     */
    public function testEIP2930GetFromAddress()
    {
        $transaction = new EIP2930Transaction($this->tx2930());
        $transaction->sign(self::PK);

        $this->assertEquals($this->expectedAddress(), $transaction->getFromAddress());
    }

    /**
     * testEIP1559GetFromAddressFromSignature
     *
     * @return void
     */
    public function testEIP1559GetFromAddressFromSignature()
    {
        $signed = new EIP1559Transaction($this->tx1559());
        $signed->sign(self::PK);

        // a transaction restored from its serialized form recovers the sender
        // from r/s/v
        $restored = new EIP1559Transaction('0x' . $signed->serialize());
        $this->assertEquals($this->expectedAddress(), $restored->getFromAddress());
    }

    /**
     * testEIP2930GetFromAddressFromSignature
     *
     * @return void
     */
    public function testEIP2930GetFromAddressFromSignature()
    {
        $signed = new EIP2930Transaction($this->tx2930());
        $signed->sign(self::PK);

        $restored = new EIP2930Transaction('0x' . $signed->serialize());
        $this->assertEquals($this->expectedAddress(), $restored->getFromAddress());
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

        (new EIP1559Transaction($this->tx1559()))->getFromAddress();
    }

    /**
     * testFromAttributeIsReturnedAsIs
     *
     * @return void
     */
    public function testFromAttributeIsReturnedAsIs()
    {
        $transaction = new EIP1559Transaction($this->tx1559());
        $transaction['from'] = '0x3535353535353535353535353535353535353535';

        $this->assertEquals('0x3535353535353535353535353535353535353535', $transaction->getFromAddress());
    }

    /**
     * testArrayAccess
     *
     * @return void
     */
    public function testArrayAccess()
    {
        $transaction = new EIP1559Transaction($this->tx1559());

        $this->assertTrue(isset($transaction['nonce']));
        $this->assertTrue(isset($transaction->nonce));
        $this->assertEquals('0x15', $transaction['nonce']);
        $this->assertEquals('0x15', $transaction->nonce);
        $this->assertFalse(isset($transaction['unknown']));
        $this->assertNull($transaction['unknown']);

        $transaction['nonce'] = '0x16';
        $this->assertEquals('0x16', $transaction['nonce']);

        unset($transaction['nonce']);
        $this->assertFalse(isset($transaction['nonce']));
        // unsetting twice and unsetting an unknown key are no-ops
        unset($transaction['nonce']);
        unset($transaction['unknown']);

        $transaction = new EIP1559Transaction($this->tx1559());
        unset($transaction->nonce);
        $this->assertFalse(isset($transaction->nonce));

        // an unknown key is ignored
        $before = $transaction->getTxData();
        $transaction['unknown'] = 'value';
        $this->assertEquals($before, $transaction->getTxData());
    }

    /**
     * testGetTxDataAndToString
     *
     * @return void
     */
    public function testGetTxDataAndToString()
    {
        $transaction = new EIP1559Transaction($this->tx1559());

        $this->assertIsArray($transaction->txData);
        $this->assertEquals($transaction->hash(false), (string) $transaction);
    }

    /**
     * testHashWithSignature
     *
     * @return void
     */
    public function testHashWithSignature()
    {
        $util = new Util;

        $transaction = new EIP1559Transaction($this->tx1559());
        $this->assertNotEmpty($transaction->hash(true));
        $this->assertNotEquals($transaction->hash(false), $transaction->hash(true));

        $signed = new EIP1559Transaction($this->tx1559());
        $signed->sign(self::PK);
        $this->assertEquals(
            $util->sha3(hex2bin($signed->serialize())),
            $signed->hash(true)
        );
    }

    /**
     * testAccessList
     *
     * @return void
     */
    public function testAccessList()
    {
        $transaction = new EIP2930Transaction(array_merge($this->tx2930(), [
            'accessList' => [
                [
                    'address' => '0x3535353535353535353535353535353535353535',
                    'storageKeys' => [
                        '0x0000000000000000000000000000000000000000000000000000000000000000',
                    ],
                ],
            ],
        ]));

        $this->assertIsArray($transaction['accessList']);
        $this->assertNotEmpty($transaction->serialize());
    }

    /**
     * testAccessListOnScalarFieldIsRejected
     *
     * @return void
     */
    public function testAccessListOnScalarFieldIsRejected()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('nonce should\'t be array.');

        new EIP2930Transaction(array_merge($this->tx2930(), ['nonce' => [1]]));
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

        new EIP1559Transaction(array_merge($this->tx1559(), ['to' => '0x' . str_repeat('11', 21)]));
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

        new EIP1559Transaction(array_merge($this->tx1559(), ['to' => str_repeat('z', 21)]));
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

        (new EIP1559Transaction($this->tx1559()))->sign('not a key');
    }

    /**
     * testBaseTypeTransaction
     * The base class is usable on its own for the legacy (0x00) type.
     *
     * @return void
     */
    public function testBaseTypeTransaction()
    {
        $transaction = new TypeTransaction($this->tx2930());

        $this->assertNotEmpty($transaction->serialize());
        $this->assertNotEmpty($transaction->hash(false));
        $this->assertNotEmpty($transaction->hash(true));

        $transaction->sign(self::PK);
        $this->assertEquals($this->expectedAddress(), $transaction->getFromAddress());
    }

    /**
     * testBaseTypeTransactionSignInvalidPrivateKey
     *
     * @return void
     */
    public function testBaseTypeTransactionSignInvalidPrivateKey()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Private key should be hex encoded string');

        (new TypeTransaction($this->tx2930()))->sign('not a key');
    }

    /**
     * testMagicSetUsesSetter
     *
     * @return void
     */
    public function testMagicSetUsesSetter()
    {
        $transaction = new TypeTransactionWithSetter($this->tx2930());
        $transaction->something = 'value';

        $this->assertEquals('value', $transaction->setterCalled);
    }

    /**
     * testMagicSetFallsBackToOffsetSet
     *
     * @return void
     */
    public function testMagicSetFallsBackToOffsetSet()
    {
        $transaction = new TypeTransaction($this->tx2930());
        $transaction->nonce = '0x16';

        $this->assertEquals('0x16', $transaction['nonce']);
        // an unknown key is ignored
        $before = $transaction->getTxData();
        $transaction->unknown = 'value';
        $this->assertEquals($before, $transaction->getTxData());
    }

    /**
     * testEIP2930HashWithSignature
     *
     * @return void
     */
    public function testEIP2930HashWithSignature()
    {
        $util = new Util;

        $transaction = new EIP2930Transaction($this->tx2930());
        $this->assertNotEmpty($transaction->hash(true));
        $this->assertNotEquals($transaction->hash(false), $transaction->hash(true));

        $signed = new EIP2930Transaction($this->tx2930());
        $signed->sign(self::PK);
        $this->assertEquals(
            $util->sha3(hex2bin($signed->serialize())),
            $signed->hash(true)
        );
    }

    /**
     * testCheckedArrayField
     *
     * @return void
     */
    public function testCheckedArrayField()
    {
        $transaction = new TypeTransactionWithCheckedArray([
            'list' => ['0x1', '0', ''],
        ]);

        // zeros are trimmed and the value is kept as is otherwise
        $this->assertEquals(['0x1', '', ''], $transaction['list']);
    }

    /**
     * testCheckedArrayFieldTooLong
     *
     * @return void
     */
    public function testCheckedArrayFieldTooLong()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('list exceeds the length limit.');

        new TypeTransactionWithCheckedArray(['list' => ['1', '2', '3', '4', '5']]);
    }

    /**
     * testConstructorWithInvalidString
     * A non hex string leaves the transaction empty instead of throwing.
     *
     * @return void
     */
    public function testConstructorWithInvalidString()
    {
        $transaction = new EIP1559Transaction('not a hex string');

        $this->assertEmpty($transaction->getTxData());
    }
}
