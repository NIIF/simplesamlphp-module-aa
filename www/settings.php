<?php

/**
 * The _include script registers a autoloader for the simpleSAMLphp libraries. It also
 * initializes the simpleSAMLphp config class with the correct path.
 */
require_once('_include.php');


/* Load simpleSAMLphp, configuration and metadata */
$config = SimpleSAML_Configuration::getInstance();
$session = SimpleSAML_Session::getInstance();

SimpleSAML_Utilities::requireAdmin();

$aaconfig = SimpleSAML_Configuration::getConfig('module_aa.php');

$resolver = $aaconfig->getValue('resolver', '');
$data = array();
if ($resolver == "PDO"){
	$data['fid'] = $aaconfig->getValue('fid_attribute_name', '');
	$data['select'] = $aaconfig->getValue('select', '');
	$data['mapping'] = $aaconfig->getArray('spid_urnregexp_map', '');
	$template = 'aa:settings-pdo-tpl.php';
}

if ($resolver == 'ExampleStatic'){
	$data['attributes'] = $aaconfig->getArray('attributes');
	$data['resolver'] = 'ExampleStatic';
	$template = 'aa:settings-examplestatic-tpl.php';
}

$t = new SimpleSAML_XHTML_Template($config, $template, 'aa:aa');
$t->data['data'] = $data;
$t->show();

?>
