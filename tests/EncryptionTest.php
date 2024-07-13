<?php

/*
 * Encryption addon for Bear Framework
 * https://github.com/ivopetkov/encryption-bearframework-addon
 * Copyright (c) Ivo Petkov
 * Free to use under the MIT license.
 */

/**
 * @runTestsInSeparateProcesses
 */
class EncryptionTest extends BearFramework\AddonTests\PHPUnitTestCase
{

    /**
     * 
     */
    public function testEncryptDecrypt()
    {
        $app = $this->getApp();
        $text = $this->generateString(10000000);
        $value = $app->encryption->encrypt($text);
        $this->assertTrue($app->encryption->decrypt($value) === $text);
    }

    /**
     * 
     */
    public function testOldFormatEncryptDecrypt()
    {
        $app = $this->getApp();
        $text = 'UG4VNRiVGVSa0Saf1flTEFqQbZnL8rNjSQGLQWWrTH6zeKOuLQuTq2wiA46S9fJrUgIHRMu6uSEU1Rqg6eilSY7K5llijOoSTuQC';
        $key = 'secret1';
        $encryptedText = '1QXXy6VDiFQbIjdrligWeE5zcWd0bFFLR3hjTnRyekIrejdKQmI2N1pLbEIrNjZhZnJLNXpaaCtJbkhGSUU1bTA3ZVRGdWtHT3BWRDVDQlcraFBYMlBFUXJPUnFHM284WFFhSHdCT0Vxc3RmS09xbzMwSFJNbjhmU2NPRFdzQitBZkRwVkh5ZENTTDBpeTkwS21ReEo3QVN5Z0xkT0hrRFlmZ3d4dz09'; // base64 encoded
        $this->assertTrue($app->encryption->decrypt(base64_decode($encryptedText), $key) === $text);
    }

    /**
     * 
     */
    public function testKeyPairEncryptDecrypt()
    {
        $app = $this->getApp();
        $text = $this->generateString(10000000);
        list($privateKey, $publicKey) = $app->encryption->generateKeyPair();
        $value = $app->encryption->encryptWithPublicKey($text, $publicKey);
        $this->assertTrue($app->encryption->decryptWithPrivateKey($value, $privateKey) === $text);
    }

    /**
     * 
     */
    public function testInvalidyDecrypt()
    {
        $app = $this->getApp();
        $this->assertTrue($app->encryption->decrypt('123') === null);
        $this->assertTrue($app->encryption->decryptWithPrivateKey('123', 'key') === null);
    }

    /**
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
