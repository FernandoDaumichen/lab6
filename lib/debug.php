<?php

function debug($statement) {
    $clargs = getopt('v');
    if (count($clargs) > 0 && array_key_exists('v', $clargs)) {
        echo $statement;
    }
}

?>