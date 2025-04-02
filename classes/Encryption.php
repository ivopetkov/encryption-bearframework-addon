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
     * @var array
     */
    private $options = [];

    /**
     * 
     * @param array $options Available values: internalEncryptSchemaVersion
     */
    public function __construct(array $options = [])
    {
        $this->options = $options;
    }

    /**
     * Encrypts the value provided. The default key will be used if none specified.
     * 
     * @param string $value
     * @param string $key
     * @return string
     */
    public function encrypt(string $value, ?string $key = null): string
    {
        if ($key === null) {
            $key = $this->getDefaultKey();
        }
        if (isset($this->options['internalEncryptSchemaVersion'])) {
            if ($this->options['internalEncryptSchemaVersion'] === 1) { // schema version 1
                $cypher = 'AES-256-GCM';
                $iv = random_bytes(openssl_cipher_iv_length($cypher));
                $tag = null;
                $content = openssl_encrypt($value, $cypher, $key, 0, $iv, $tag);
                if ($content === false) {
                    throw new \Exception('Cannot encrypt value (' . openssl_error_string() . ')!');
                }
                return json_encode([1, base64_encode($iv), base64_encode($tag)]) . $content; // first value is schema version
            } else {
                throw new \Exception('Invalid internalEncryptSchemaVersion value!');
            }
        }
        // current schema version (2)
        $cypher = 'AES-256-GCM';
        $iv = random_bytes(openssl_cipher_iv_length($cypher));
        $tag = null;
        $content = openssl_encrypt($value, $cypher, $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($content === false) {
            throw new \Exception('Cannot encrypt value (' . openssl_error_string() . ')!');
        }
        return json_encode([2, base64_encode($iv), base64_encode($tag)]) . $content; // first value is schema version
    }

    /**
     * Encrypts the file provided. The default key will be used if none specified.
     * 
     * @param string $sourceFile
     * @param string $destinationFile
     * @param string|null $key
     * @param string $prefix
     * @return void
     */
    private function _encryptFile(string $sourceFile, string $destinationFile, ?string $key = null, string $prefix = ''): void
    {
        if ($key === null) {
            $key = $this->getDefaultKey();
        }
        $cypher = 'AES-256-GCM';
        $ivLength = openssl_cipher_iv_length($cypher);
        $iv = random_bytes($ivLength);

        $sourceFilePointer = fopen($sourceFile, 'rb');
        if ($sourceFilePointer === false) {
            throw new \Exception('Cannot open source file!');
        }
        $destinationFilePointer = fopen($destinationFile, 'w');
        if ($destinationFilePointer === false) {
            fclose($sourceFilePointer);
            throw new \Exception('Cannot open destination file!');
        }
        try {
            if ($prefix !== '') {
                fwrite($destinationFilePointer, $prefix);
            }
            fwrite($destinationFilePointer, json_encode([3, base64_encode($iv)])); // first value is schema version

            $nextIv = $iv;
            while (!feof($sourceFilePointer)) {
                $tag = null;
                $content = openssl_encrypt(fread($sourceFilePointer, $ivLength * 100000), $cypher, $key, OPENSSL_RAW_DATA, $nextIv, $tag, '', 16);
                if ($content === false) {
                    throw new \Exception('Cannot encrypt value (' . openssl_error_string() . ')!');
                }
                $nextIv = substr($content, 0, $ivLength);
                fwrite($destinationFilePointer, $content);
                fwrite($destinationFilePointer, $tag); // tag is 16 bytes long
            }
            fclose($sourceFilePointer);
            fclose($destinationFilePointer);
        } catch (\Exception $e) {
            fclose($sourceFilePointer);
            fclose($destinationFilePointer);
            throw $e;
        }
    }

    /**
     * Encrypts the file provided. The default key will be used if none specified.
     * 
     * @param string $sourceFile
     * @param string $destinationFile
     * @param string $key
     * @return void
     */
    public function encryptFile(string $sourceFile, string $destinationFile, ?string $key = null): void
    {
        $this->_encryptFile($sourceFile, $destinationFile, $key, '');
    }

    /**
     * Decrypts the value provided. The default key will be used if none specified.
     * 
     * @param string $value
     * @param string $key
     * @return string|null
     */
    public function decrypt(string $value, ?string $key = null): ?string
    {
        if ($key === null) {
            $key = $this->getDefaultKey();
        }
        if (substr($value, 0, 1) === '[') { // new format
            $separatorIndex = strpos($value, ']');
            if ($separatorIndex === false) {
                return null;
            }
            $config = json_decode(substr($value, 0, $separatorIndex + 1));
            if ($config !== null) {
                if ($config[0] === 3) { // schema version 3 - file
                    $cypher = 'AES-256-GCM';
                    $ivLength = openssl_cipher_iv_length($cypher);
                    $iv = base64_decode($config[1]);
                    $content = substr($value, $separatorIndex + 1);
                    $result = '';
                    $chunkLength = $ivLength * 100000 + 16; // + 16 for the tag
                    $chunksCount = ceil(strlen($content) / $chunkLength);
                    $nextIv = $iv;
                    for ($i = 0; $i < $chunksCount; $i++) {
                        $contentChunk = substr($content, $i * $chunkLength, $chunkLength);
                        $currentChunkLength = strlen($contentChunk);
                        $chunkResult = openssl_decrypt(substr($contentChunk, 0, $currentChunkLength - 16), $cypher, $key, OPENSSL_RAW_DATA, $nextIv, substr($contentChunk, $currentChunkLength - 16));
                        if ($chunkResult === false) {
                            return null;
                        }
                        $result .= $chunkResult;
                        $nextIv = substr($contentChunk, 0, $ivLength);
                    }
                    return $result;
                } else if ($config[0] === 2) { // schema version 2
                    $cypher = 'AES-256-GCM';
                    $iv = base64_decode($config[1]);
                    $tag = base64_decode($config[2]);
                    $content = substr($value, $separatorIndex + 1);
                    $result = openssl_decrypt($content, $cypher, $key, OPENSSL_RAW_DATA, $iv, $tag);
                    if ($result === false) {
                        return null;
                    }
                    return $result;
                } elseif ($config[0] === 1) { // schema version 1
                    $cypher = 'AES-256-GCM';
                    $iv = base64_decode($config[1]);
                    $tag = base64_decode($config[2]);
                    $content = substr($value, $separatorIndex + 1);
                    $result = openssl_decrypt($content, $cypher, $key, 0, $iv, $tag);
                    if ($result === false) {
                        return null;
                    }
                    return $result;
                }
            }
            return null;
        }
        // old format
        $cypher = 'AES-256-CBC';
        $ivLength = openssl_cipher_iv_length($cypher);
        $iv = substr($value, 0, $ivLength);
        $tag = null;
        $content = substr($value, $ivLength);
        $result = openssl_decrypt($content, $cypher, $key, 0, $iv, $tag);
        if ($result === false) {
            return null;
        }
        return $result;
    }

    /**
     * Decrypts the file provided. The default key will be used if none specified.
     * 
     * @param string $sourceFile
     * @param string $destinationFile
     * @param string|null $key
     * @return void
     */
    public function decryptFile(string $sourceFile, string $destinationFile, ?string $key = null): void
    {
        $this->_decryptFile($sourceFile, $destinationFile, $key, 0);
    }

    /**
     * Decrypts the file provided. The default key will be used if none specified.
     * 
     * @param string $sourceFile
     * @param string $destinationFile
     * @param string|null $key
     * @param int $bytesToSkip
     * @return void
     */
    public function _decryptFile(string $sourceFile, string $destinationFile, ?string $key = null, int $bytesToSkip = 0): void
    {
        if ($key === null) {
            $key = $this->getDefaultKey();
        }

        $sourceFilePointer = fopen($sourceFile, 'rb');
        if ($sourceFilePointer === false) {
            throw new \Exception('Cannot open source file!');
        }
        $destinationFilePointer = fopen($destinationFile, 'w');
        if ($destinationFilePointer === false) {
            fclose($sourceFilePointer);
            throw new \Exception('Cannot open destination file!');
        }

        try {
            if ($bytesToSkip > 0) {
                fseek($sourceFilePointer, $bytesToSkip);
            }
            $valueSlice = fread($sourceFilePointer, 1000);
            if (substr($valueSlice, 0, 1) === '[') {
                $separatorIndex = strpos($valueSlice, ']');
                if ($separatorIndex === false) {
                    throw new \Exception('Invalid value!');
                }
                fseek($sourceFilePointer, $separatorIndex + 1 + $bytesToSkip);
                $config = json_decode(substr($valueSlice, 0, $separatorIndex + 1));
                if ($config !== null) {
                    if ($config[0] === 3) { // schema version 3 - file
                        $cypher = 'AES-256-GCM';
                        $ivLength = openssl_cipher_iv_length($cypher);
                        $iv = base64_decode($config[1]);
                        $chunkLength = $ivLength * 100000 + 16; // + 16 for the tag
                        $nextIv = $iv;
                        while (!feof($sourceFilePointer)) {
                            $contentChunk = fread($sourceFilePointer, $chunkLength);
                            $currentChunkLength = strlen($contentChunk);
                            $chunkResult = openssl_decrypt(substr($contentChunk, 0, $currentChunkLength - 16), $cypher, $key, OPENSSL_RAW_DATA, $nextIv, substr($contentChunk, $currentChunkLength - 16));
                            if ($chunkResult === false) {
                                throw new \Exception('Cannot decrypt value (' . openssl_error_string() . ')!');
                            }
                            fwrite($destinationFilePointer, $chunkResult);
                            $nextIv = substr($contentChunk, 0, $ivLength);
                        }
                    } else if ($config[0] === 2) { // schema version 2
                        $content = '';
                        while (!feof($sourceFilePointer)) {
                            $content .= fread($sourceFilePointer, 100000);
                        }
                        $cypher = 'AES-256-GCM';
                        $iv = base64_decode($config[1]);
                        $tag = base64_decode($config[2]);
                        $result = openssl_decrypt($content, $cypher, $key, OPENSSL_RAW_DATA, $iv, $tag);
                        if ($result === false) {
                            throw new \Exception('Cannot decrypt value (' . openssl_error_string() . ')!');
                        }
                        file_put_contents($destinationFile, $result);
                    } else if ($config[0] === 1) { // schema version 1
                        $content = '';
                        while (!feof($sourceFilePointer)) {
                            $content .= fread($sourceFilePointer, 100000);
                        }
                        $cypher = 'AES-256-GCM';
                        $iv = base64_decode($config[1]);
                        $tag = base64_decode($config[2]);
                        $result = openssl_decrypt($content, $cypher, $key, 0, $iv, $tag);
                        if ($result === false) {
                            throw new \Exception('Cannot decrypt value (' . openssl_error_string() . ')!');
                        }
                        file_put_contents($destinationFile, $result);
                    } else {
                        throw new \Exception('Unsupported schema version!');
                    }
                } else {
                    throw new \Exception('Invalid value!');
                }
            }
            fclose($sourceFilePointer);
            fclose($destinationFilePointer);
        } catch (\Exception $e) {
            fclose($sourceFilePointer);
            fclose($destinationFilePointer);
            throw $e;
        }
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
     * Encrypts the file provided with the public key specified.
     * 
     * @param string $sourceFile
     * @param string $destinationFile
     * @param string $publicKey
     * @return void
     */
    public function encryptFileWithPublicKey(string $sourceFile, string $destinationFile, string $publicKey): void
    {
        $key = $this->generateKey(rand(100, 200));
        $encryptedKey = '';
        $result = openssl_public_encrypt($key, $encryptedKey, $publicKey, OPENSSL_PKCS1_PADDING);
        if ($result === false) {
            throw new \Exception('Cannot encrypt key (' . strlen($key) . ')!');
        }
        $this->_encryptFile($sourceFile, $destinationFile, $key, base64_encode($encryptedKey));
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
     * Decrypts the file provided with the private key specified.
     *
     * @param string $sourceFile
     * @param string $destinationFile
     * @param string $privateKey
     * @return void
     */
    public function decryptFileWithPrivateKey(string $sourceFile, string $destinationFile, string $privateKey): void
    {
        $sourceFilePointer = fopen($sourceFile, 'rb');
        if ($sourceFilePointer === false) {
            throw new \Exception('Cannot open source file!');
        }
        $valueSlice = fread($sourceFilePointer, 1000);
        $separatorIndex = strpos($valueSlice, '[');
        if ($separatorIndex === false) {
            throw new \Exception('Invalid value!');
        }
        $encryptedKey = base64_decode(substr($valueSlice, 0, $separatorIndex));

        $decryptedKey = null;
        $result = openssl_private_decrypt($encryptedKey, $decryptedKey, $privateKey);
        if ($result === false) {
            throw new \Exception('Cannot decrypt key)!');
        }
        $this->_decryptFile($sourceFile, $destinationFile, $decryptedKey, $separatorIndex);
    }

    /**
     * Returns the default key.
     * 
     * @return string
     */
    public function getDefaultKey(): string
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
