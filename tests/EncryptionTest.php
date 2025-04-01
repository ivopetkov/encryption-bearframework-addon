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
        $this->assertTrue(substr($value, 0, 4) === '[2,"');
        $this->assertTrue($app->encryption->decrypt($value) === $text);
    }

    /**
     * 
     */
    public function testEncryptDecryptSchemaVersion1()
    {
        $app = $this->getApp();
        $encryption = new \IvoPetkov\BearFrameworkAddons\Encryption(['internalEncryptSchemaVersion' => 1]);
        $text = $this->generateString(10000000);
        $value = $encryption->encrypt($text);
        $this->assertTrue(substr($value, 0, 4) === '[1,"');
        $this->assertTrue($encryption->decrypt($value) === $text);
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
    public function testEncryptDecryptFile()
    {
        $app = $this->getApp();
        $tempDir = $this->getTempDir();

        $sourceFile = $tempDir . '/file.txt';
        $encryptedFile = $tempDir . '/file.txt.enc';
        $decryptedFile = $tempDir . '/file.txt.dec';
        $text = $this->generateString(10000000);
        $this->makeFile($sourceFile, $text);
        $app->encryption->encryptFile($sourceFile, $encryptedFile, '123');
        $encryptedText = file_get_contents($encryptedFile);
        $this->assertTrue(substr($encryptedText, 0, 4) === '[3,"');
        $this->assertTrue($app->encryption->decrypt($encryptedText, '123') === $text);
        $app->encryption->decryptFile($encryptedFile, $decryptedFile, '123');
        $this->assertTrue(file_get_contents($decryptedFile) === $text);

        $text2 = $this->generateString(10000000);
        $encryptedFile2 = $tempDir . '/file2.txt.enc';
        $decryptedFile2 = $tempDir . '/file2.txt.dec';
        $this->makeFile($encryptedFile2, $app->encryption->encrypt($text2, '234'));
        $app->encryption->decryptFile($encryptedFile2, $decryptedFile2, '234');
        $this->assertTrue(file_get_contents($decryptedFile2) === $text2);
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
     * @return void
     */
    public function testKeyPairEncryptDecryptFile()
    {
        $app = $this->getApp();
        $tempDir = $this->getTempDir();

        list($privateKey, $publicKey) = $app->encryption->generateKeyPair();

        $sourceFile = $tempDir . '/file.txt';
        $encryptedFile = $tempDir . '/file.txt.enc';
        $decryptedFile = $tempDir . '/file.txt.dec';
        $text = $this->generateString(10000000);
        $this->makeFile($sourceFile, $text);
        $app->encryption->encryptFileWithPublicKey($sourceFile, $encryptedFile, $publicKey);
        $encryptedText = file_get_contents($encryptedFile);
        $this->assertTrue(strpos(substr($encryptedText, 0, 1000), '[3,"') !== false);
        $this->assertTrue($app->encryption->decryptWithPrivateKey($encryptedText, $privateKey) === $text);
        $app->encryption->decryptFileWithPrivateKey($encryptedFile, $decryptedFile, $privateKey);
        $this->assertTrue(file_get_contents($decryptedFile) === $text);

        $text2 = $this->generateString(10000000);
        $encryptedFile2 = $tempDir . '/file2.txt.enc';
        $decryptedFile2 = $tempDir . '/file2.txt.dec';
        $this->makeFile($encryptedFile2, $app->encryption->encryptWithPublicKey($text2, $publicKey));
        $app->encryption->decryptFileWithPrivateKey($encryptedFile2, $decryptedFile2, $privateKey);
        $this->assertTrue(file_get_contents($decryptedFile2) === $text2);
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
