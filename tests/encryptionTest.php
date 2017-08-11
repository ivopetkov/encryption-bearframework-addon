<?php

/*
 * Encryption addon for Bear Framework
 * https://github.com/ivopetkov/encryption-bearframework-addon
 * Copyright (c) 2017 Ivo Petkov
 * Free to use under the MIT license.
 */

/**
 * @runTestsInSeparateProcesses
 */
class EncryptionTest extends BearFrameworkAddonTestCase
{

    /**
     * 
     */
    public function testEncrypt()
    {
        $app = $this->getApp();
        $value = $app->encryption->encrypt('123');
        $this->assertTrue($app->encryption->decrypt($value) === '123');
    }

    /**
     * 
     */
    public function testInvalidyDecrypt()
    {
        $app = $this->getApp();
        $this->assertTrue($app->encryption->decrypt('123') === null);
    }

}
