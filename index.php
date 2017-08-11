<?php

/*
 * Encryption addon for Bear Framework
 * https://github.com/ivopetkov/encryption-bearframework-addon
 * Copyright (c) 2017 Ivo Petkov
 * Free to use under the MIT license.
 */

use BearFramework\App;

$app = App::get();
$context = $app->context->get(__FILE__);

$context->classes
        ->add('IvoPetkov\BearFrameworkAddons\Encryption', 'classes/Encryption.php');

$app->shortcuts
        ->add('encryption', function() {
            return new IvoPetkov\BearFrameworkAddons\Encryption();
        });
