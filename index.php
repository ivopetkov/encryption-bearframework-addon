<?php

/*
 * Encryption addon for Bear Framework
 * https://github.com/ivopetkov/encryption-bearframework-addon
 * Copyright (c) Ivo Petkov
 * Free to use under the MIT license.
 */

use BearFramework\App;

$app = App::get();
$context = $app->contexts->get(__DIR__);

$context->classes
        ->add('IvoPetkov\BearFrameworkAddons\Encryption', 'classes/Encryption.php');

$app->shortcuts
        ->add('encryption', function() {
            return new IvoPetkov\BearFrameworkAddons\Encryption();
        });
