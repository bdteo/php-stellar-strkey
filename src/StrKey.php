<?php
namespace Bdteo\Stellar;

use Base32\Base32;
use PBurggraf\CRC\CRC16\Xmodem;

/**
 * TODO: add tests
 * Class StrKey
 */
class StrKey
{
    public const VERSION_BYTES = [
        "ed25519PublicKey" => 6 << 3, //G
        "ed25519SecretSeed" => 18 << 3, //S
        "preAuthTx" => 19 << 3, //T
        "sha256Hash" => 23 << 3 //X
    ];


    /**
     * @param string $publicKey
     * @return mixed
     */
    public static function isValidStellarAddress(string $publicKey)
    {
        return self::isValidEd25519PublicKey($publicKey);
    }

    /**
     * Encodes data to strkey ed25519 public key.
     * @param string $data
     * @return string
     */
    public static function encodeEd25519PublicKey(string $data)
    {
        return self::encodeCheck("ed25519PublicKey", $data);
    }

    /**
     * Decodes strkey ed25519 public key to raw data.
     * @param string $data
     * @return string
     * @throws \ErrorException
     */
    public static function decodeEd25519PublicKey(string $data)
    {
        return self::decodeCheck("ed25519PublicKey", $data);
    }

    /**
     * Returns true if the given Stellar public key is a valid ed25519 public key.
     * @param string $publicKey
     * @return bool
     */
    public static function isValidEd25519PublicKey(string $publicKey)
    {
        return self::isValid("ed25519PublicKey", $publicKey);
    }

    /**
     * Encodes data to strkey ed25519 seed.
     * @param string $data
     * @return string
     */
    public static function encodeEd25519SecretSeed(string $data)
    {
        return self::encodeCheck("ed25519SecretSeed", $data);
    }

    /**
     * Decodes strkey ed25519 seed to raw data.
     * @param string $data
     * @return string
     * @throws \ErrorException
     */
    public static function decodeEd25519SecretSeed(string $data)
    {
        return self::decodeCheck("ed25519SecretSeed", $data);
    }

    /**
     * Returns true if the given Stellar secret key is a valid ed25519 secret seed.
     * @param string $seed
     * @return bool
     */
    public static function isValidEd25519SecretSeed(string $seed)
    {
        return self::isValid("ed25519SecretSeed", $seed);
    }

    /**
     * Encodes data to strkey preAuthTx.
     * @param string $data
     * @return string
     */
    public static function encodePreAuthTx(string $data)
    {
        return self::encodeCheck("preAuthTx", $data);
    }

    /**
     * Decodes strkey PreAuthTx to raw data.
     * @param string $data
     * @return string
     * @throws \ErrorException
     */
    public static function decodePreAuthTx(string $data)
    {
        return self::decodeCheck("preAuthTx", $data);
    }

    /**
     * Encodes data to strkey sha256 hash.
     * @param string $data
     * @return string
     */
    public static function encodeSha256Hash(string $data)
    {
        return self::encodeCheck("sha256Hash", $data);
    }

    /**
     * Decodes strkey sha256 hash to raw data.
     * @param string $data
     * @return string
     * @throws \ErrorException
     */
    public static function decodeSha256Hash(string $data)
    {
        return self::decodeCheck("sha256Hash", $data);
    }

    /**
     * @param string $versionByteName
     * @param string $encoded
     * @return bool
     */
    private static function isValid(string $versionByteName, string $encoded)
    {
        if ($encoded && strlen($encoded) != 56) {
            return false;
        }

        try {
            $decoded = self::decodeCheck($versionByteName, $encoded);
            if (strlen($decoded) !== 32) {
                return false;
            }
        } catch (\Exception $e) {
            return false;
        }
        return true;
    }

    /**
     * @param string $versionByteName
     * @param string $encoded
     * @return string
     * @throws \ErrorException
     */
    public static function decodeCheck(string $versionByteName, string $encoded)
    {

        $decoded = Base32::decode($encoded);
        $versionByte = ord($decoded[0]);
        $payload = substr($decoded, 0, -2);
        $data = substr($payload, 1);
        $checksum = substr($decoded, -2);

        if ($encoded != Base32::encode($decoded)) {
            throw new \InvalidArgumentException('Invalid encoding');
        }

        $expectedVersion = self::array_get(self::VERSION_BYTES, $versionByteName);

        if (!$expectedVersion) {
            throw new \InvalidArgumentException(
                "\"$versionByteName\" is not a valid version byte name"
            );
        }

        if ($versionByte !== $expectedVersion) {
            throw new \InvalidArgumentException("Invalid version byte. Expected \"$expectedVersion\", got \"$versionByte\"");
        }

        $expectedChecksum = self::calculateChecksum($payload);

        if (!self::verifyChecksum($expectedChecksum, $checksum)) {
            throw new \ErrorException('Invalid checksum');
        }

        return $data;
    }

    /**
     * @param string $versionByteName
     * @param string $data
     * @return string
     */
    private static function encodeCheck(string $versionByteName, string $data)
    {
        if (!$data) {
            throw new \InvalidArgumentException("Cannot encode null data");
        }

        $versionByte = self::array_get(self::VERSION_BYTES, $versionByteName);

        if (!$versionByte) {
            throw new \InvalidArgumentException(
                "\"versionByteName\" is not a valid version byte name. Expected one of \"ed25519PublicKey\", \"ed25519SecretSeed\", \"preAuthTx\", \"sha256Hash\""
            );
        }

        $payload = pack('C', $versionByte) . $data;
        $checksum = self::calculateChecksum($payload);
        $unEncoded =  $payload . $checksum;

        return Base32::encode($unEncoded);
    }

    /**
     * @param string $payload
     * @return string
     */
    private static function calculateChecksum(string $payload)
    {
        // This code calculates CRC16-XModem checksum of payload
        // and returns it in little-endian order

        $crcCalculator = new Xmodem();

        return pack('v', $crcCalculator->calculate($payload));
    }

    /**
     * @param string $expected
     * @param string $actual
     * @return bool
     */
    private static function verifyChecksum(string $expected, string $actual) {
        if (strlen($expected) !== strlen($actual)) {
            return false;
        }

        if (strlen($expected) === 0) {
            return true;
        }

        for ($i = 0; $i < strlen($expected); $i++) {
            if ($expected[$i] !== $actual[$i]) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array $array
     * @param string $get
     * @param null $default
     * @return mixed|null
     */
    private static function array_get(array $array, string $get, $default = null)
    {
        return isset($array[$get])
            ? $array[$get]
            : $default;
    }
}
