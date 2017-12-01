<?php

/*
 * Encryption addon for Bear Framework
 * https://github.com/ivopetkov/encryption-bearframework-addon
 * Copyright (c) 2017 Ivo Petkov
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
     * The cipher method
     * @var string 
     */
    private $cipher = 'AES-256-CBC';

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
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cipher));
        return $iv . openssl_encrypt($value, $this->cipher, $key, 0, $iv);
    }

    /**
     * Decrypts the value provided. The default key will be used if none specified.
     * 
     * @param string $value
     * @param string $key
     * @return string
     */
    public function decrypt(string $value, string $key = null): ?string
    {
        if ($key === null) {
            $key = $this->getDefaultKey();
        }
        $ivLength = openssl_cipher_iv_length($this->cipher);
        $iv = substr($value, 0, $ivLength);
        $result = @openssl_decrypt(substr($value, $ivLength), $this->cipher, $key, 0, $iv);
        if ($result === false) {
            return null;
        }
        return $result;
    }

    /**
     * Returns the default key.
     */
    private function getDefaultKey()
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
                $value = md5(openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cipher)) . uniqid('', true) . rand(0, 999999999));
                $app->data->set($app->data->make($dataKey, $value));
            }
            $app->cache->set($app->cache->make($cacheKey, $value));
        }
        $this->cache['defaultKey'] = $value;
        return $value;
    }

}
