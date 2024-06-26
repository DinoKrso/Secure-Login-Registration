<?php
error_reporting(E_ERROR | E_PARSE);
require("vendor/autoload.php");


$openapi = \OpenApi\Generator::scan(['./api']);


header('Content-Type: application/json');
echo $openapi->toJson();
