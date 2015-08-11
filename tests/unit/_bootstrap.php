<?php
// Here you can initialize variables that will be available to your tests

$di = new \Phalcon\DI\FactoryDefault\CLI();

$di->set(
	'console',
	function () {
		$console = new \Phalcon\CLI\Console();
		
		return $console;
	}
);