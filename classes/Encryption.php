<?php

/*
 * Encryption addon for Bear Framework
 * https://github.com/ivopetkov/encryption-bearframework-addon
 * Copyright (c) Ivo Petkov
 * Free to use under the MIT license.
 */

namespace IvoPetkov\BearFrameworkAddons;

use BearFramework\App;

/**
 *
 */
class Encryption
{

    /**
     *
     * @var array 
     */
    private $cache = [];

    /**
     * 
     */
    public function __construct()
    {
    }

    /**
     * Encrypts the value provided. The default key will be used if none specified.
     * 
     * @param string $value
     * @param string $key
     * @return string
     */
    public function encrypt(string $value, string $key = null): string
    {
        if ($key === null) {
            $key = $this->getDefaultKey();
        }
        $cypher = 'AES-256-GCM';
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($cypher));
        $tag = null;
        $content = openssl_encrypt($value, $cypher, $key, 0, $iv, $tag);
        return json_encode([1, base64_encode($iv), base64_encode($tag)]) . $content; // first value is schema version
    }

    /**
     * Decrypts the value provided. The default key will be used if none specified.
     * 
     * @param string $value
     * @param string $key
     * @return string|null
     */
    public function decrypt(string $value, string $key = null): ?string
    {
        if ($key === null) {
            $key = $this->getDefaultKey();
        }
        if (substr($value, 0, 1) === '[') {
            $separatorIndex = strpos($value, ']');
            if ($separatorIndex === false) {
                return null;
            }
            $config = json_decode(substr($value, 0, $separatorIndex + 1));
            if ($config[0] === 1) { // schema version 1
                $cypher = 'AES-256-GCM';
                $iv = base64_decode($config[1]);
                $tag = base64_decode($config[2]);
            } else {
                return null;
            }
            $content = substr($value, $separatorIndex + 1);
        } else { // old format
            $cypher = 'AES-256-CBC';
            $ivLength = openssl_cipher_iv_length($cypher);
            $iv = substr($value, 0, $ivLength);
            $tag = null;
            $content = substr($value, $ivLength);
        }
        $result = @openssl_decrypt($content, $cypher, $key, 0, $iv, $tag);
        if ($result === false) {
            return null;
        }
        return $result;
    }

    /**
     * Encrypts the value provided with the public key specified.
     * 
     * @param string $value
     * @param string $publicKey
     * @return string
     */
    public function encryptWithPublicKey(string $value, string $publicKey): string
    {
        $key = $this->generateKey(rand(100, 200));
        $encryptedKey = '';
        $result = openssl_public_encrypt($key, $encryptedKey, $publicKey, OPENSSL_PKCS1_PADDING);
        if ($result === false) {
            throw new \Exception('Cannot encrypt key (' . strlen($key) . ')!');
        }
        return base64_encode($encryptedKey) . $this->encrypt($value, $key);
    }

    /**
     * Decrypts the value provided with the private key specified.
     * 
     * @param string $value
     * @param string $publicKey
     * @return string|null
     */
    public function decryptWithPrivateKey(string $value, string $privateKey): ?string
    {
        $separatorIndex = strpos($value, '[');
        if ($separatorIndex === false) {
            return null;
        }
        $encryptedKey = base64_decode(substr($value, 0, $separatorIndex));
        $encryptedContent = substr($value, $separatorIndex);

        $decryptedKey = null;
        $result = openssl_private_decrypt($encryptedKey, $decryptedKey, $privateKey);
        if ($result === false) {
            return null;
        }
        return $this->decrypt($encryptedContent, $decryptedKey);
    }

    /**
     * Returns the default key.
     */
    public function getDefaultKey()
    {
        if (isset($this->cache['defaultKey'])) {
            return $this->cache['defaultKey'];
        }
        $app = App::get();
        $cacheKey = 'ivopetkov-encryption-default-key';
        $value = $app->cache->getValue($cacheKey);
        if ($value === null) {
            $dataKey = 'encryption/default.key';
            $value = $app->data->getValue($dataKey);
            if ($value === null) {
                $value = $this->generateString(rand(32, 64));
                $app->data->set($app->data->make($dataKey, $value));
            }
            $app->cache->set($app->cache->make($cacheKey, $value));
        }
        $this->cache['defaultKey'] = $value;
        return $value;
    }

    /**
     * Generates a new key.
     * 
     * @param int $length
     * @return string
     */
    public function generateKey(int $length): string
    {
        return $this->generateString($length);
    }

    /**
     * Generates a new key pair.
     * 
     * @return array Returns [$privateKey, $publicKey]
     */
    public function generateKeyPair(): array
    {
        $key = openssl_pkey_new(["digest_alg" => "sha512", "private_key_bits" => 2048, "private_key_type" => OPENSSL_KEYTYPE_RSA]);
        if ($key === false) {
            throw new \Exception('Cannot generate key pair (' . openssl_error_string() . ')!');
        }
        $privateKey = '';
        openssl_pkey_export($key, $privateKey);
        $publicKey = openssl_pkey_get_details($key)['key'];
        return [$privateKey, $publicKey];
    }

    /**
     * Generates a random string.
     * 
     * @param integer $length
     * @return string
     */
    private function generateString(int $length): string
    {
        $result = '';
        $letters = str_split('qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890', 1);
        for ($i = 0; $i < $length; $i++) {
            $result .= $letters[array_rand($letters, 1)];
        }
        return $result;
    }
}
