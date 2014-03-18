<?php

/* simpleSAMLphp code here */
$aa_config = SimpleSAML_Configuration::getConfig('module_aa.php'); 
$metadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();

/* Receiving the attribute query */
$binding = SAML2_Binding::getCurrentBinding();

/* Supported binding is SOAP */
if (! ($binding instanceof SAML2_SOAP)) {
	throw new SimpleSAML_Error_BadRequest('[aa] Unsupported binding. It must be SAML2_SOAP.');	
}
SimpleSAML_Logger::debug('[aa] binding: '.var_export($binding,true));

$query = $binding->receive();
SimpleSAML_Logger::debug('[aa] query: '.var_export($query,true));

if (!($query instanceof SAML2_AttributeQuery)) {
	throw new SimpleSAML_Error_BadRequest('Invalid message received to AttributeQuery endpoint.');
}


/* Getting the related entities metadata objects */
$aaEntityId = $metadata->getMetaDataCurrentEntityID('attributeauthority-hosted');
$aaMetadata = $metadata->getMetadataConfig($aaEntityId, 'attributeauthority-hosted');

$spEntityId = $query->getIssuer();
if ($spEntityId === NULL) {
	throw new SimpleSAML_Error_BadRequest('Missing <saml:Issuer> in <samlp:AttributeQuery>.');
}
$spMetadata = $metadata->getMetaDataConfig($spEntityId, 'saml20-sp-remote');

/* Validate the query authenticity */
$client_is_authenticated = FALSE;

if (array_key_exists('SSL_CLIENT_VERIFY', $_SERVER)){
    SimpleSAML_Logger::debug('[aa] SSL_CLIENT_VERIFY: '.var_export($_SERVER['SSL_CLIENT_VERIFY'],1));
}
if (array_key_exists('SSL_CLIENT_VERIFY', $_SERVER) && $_SERVER['SSL_CLIENT_VERIFY'] != "NONE"){
	/* compare certificate fingerprints */
	$clientCertData = trim(preg_replace('/-----.* CERTIFICATE-----/','',$_SERVER['SSL_CLIENT_CERT']));
    $clientCertFingerprint = strtolower(sha1(base64_decode($clientCertData)));

	$spCertArray = SimpleSAML_Utilities::loadPublicKey($spMetadata);
	if ($clientCertFingerprint != $spCertArray['certFingerprint'][0]){
		throw new SimpleSAML_Error_Exception("[aa] The SSL certificate of the Attribute Aggregator is exists but not match with the metadata! clientCertFingerprint: ".$clientCertFingerprint." metadataCertFingerPrint: ".$spCertArray['certFingerprint'][0]);
	}
	$client_is_authenticated = TRUE;
        SimpleSAML_Logger::debug('[aa] SSL certificate is checked and valid.');	
}
else {
	SimpleSAML_Logger::debug('[aa] SSL client certificate not exists.');
}

//Has query signature?
$certs_of_query = $query->getCertificates();
SimpleSAML_Logger::debug('[aa] Count of querys certs: '.count($certs_of_query));
if (count($certs_of_query) > 0) {
	if (! sspmod_saml_Message::checkSign($spMetadata,$query)){
		throw new SimpleSAML_Error_Exception("[aa] The sign of the AttributeQuery is exists and wrong!");
	}
	$client_is_authenticated = TRUE;
        SimpleSAML_Logger::debug('[aa] AttributeQuery signature is checked and valid.');
}
else {
    SimpleSAML_Logger::debug('[aa] AttributeQuery has no signature.');
}

if (! $client_is_authenticated){
             SimpleSAML_Logger::info('[aa] AttributeQuery has not authenticity. Drop.');
             header('HTTP/1.1 401 Unauthorized');
             header('WWW-Authenticate: None',false);
             echo 'Not authenticated. No AttributeQuery signature nor SSL client certificate not available.';
             exit;
}
else {
	SimpleSAML_Logger::debug('[aa] AttributeQuery has authenticity.');
}

/* The attributes we will return. */
$nameId=$query->getNameId();
$expected_nameFormat = $aa_config->getValue('expected_nameFormat',SAML2_Const::NAMEID_PERSISTENT);
if ($aa_config->hasValue('expected_nameFormat') && ($nameId['nameFormat'] != $expected_nameFormat)){
	throw new SimpleSAML_Error_BadRequest('[aa] Bad news! NameIdFormat is not the expected (persistent is recommended)! Given: '.$nameId['nameFormat'].' expected: '. $expected_nameFormat);
}
$resolverclass = 'sspmod_aa_AttributeResolver_'.$aa_config->getValue('resolver');
 if (! class_exists($resolverclass)){
	throw new SimpleSAML_Error_Exception('[aa] There is no resolver named '.$aa_config->getValue('resolver').' in the config/module_aa.php');
}

/* Get the attributes from the Resolver */
$ar = new $resolverclass($aa_config);
$attributes = array();
$attributes = $ar->getAttributes($nameId['Value'],$spEntityId);

/* The name format of the attributes. */
//$attributeNameFormat = SAML2_Const::NAMEFORMAT_URI;
$attributeNameFormat = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';

SimpleSAML_Logger::debug('[aa] Got relay state: '.$query->getRelayState());

/* Determine which attributes we will return. */
$returnAttributes = $query->getAttributes();
if (count($returnAttributes) === 0) {
	SimpleSAML_Logger::debug('[aa] No attributes requested - return all attributes: '.var_export($attributes,true));
	$returnAttributes = $attributes;

} elseif ($query->getAttributeNameFormat() !== $attributeNameFormat) {
	SimpleSAML_Logger::debug('[aa] Requested attributes with wrong NameFormat - no attributes returned. Expected: '.$attributeNameFormat.' Got: '. $query->getAttributeNameFormat());
	$returnAttributes = array();
} else {
	foreach ($returnAttributes as $name => $values) {
		SimpleSAML_Logger::debug('[aa] Check this attribute: '.$name);
		if (!array_key_exists($name, $attributes)) {
			/* We don't have this attribute. */
			SimpleSAML_Logger::debug('[aa] We dont have this attribute, unset: '.$name);
			unset($returnAttributes[$name]);
			continue;
		}

		if (count($values) === 0) {
			/* Return all attributes. */
			$returnAttributes[$name] = $attributes[$name];
			continue;
		}

		/* Filter which attribute values we should return. */
		$returnAttributes[$name] = array_intersect($values, $attributes[$name]);
	}
}


/* SubjectConfirmation */
$sc = new SAML2_XML_saml_SubjectConfirmation();
$sc->Method = SAML2_Const::CM_BEARER;
$sc->SubjectConfirmationData = new SAML2_XML_saml_SubjectConfirmationData();
$sc->SubjectConfirmationData->NotBefore = time() - $aa_config->getInteger('timewindow');
$sc->SubjectConfirmationData->NotOnOrAfter = time() + $aa_config->getInteger('timewindow');
$sc->SubjectConfirmationData->InResponseTo = $query->getId();

/* The Assertion */
$assertion = new SAML2_Assertion();
$assertion->setSubjectConfirmation(array($sc));
$assertion->setIssuer($aaEntityId);
$assertion->setNameId($query->getNameId());
$assertion->setNotBefore(time() - $aa_config->getInteger('timewindow'));
$assertion->setNotOnOrAfter(time() + $aa_config->getInteger('timewindow'));
$assertion->setValidAudiences(array($spEntityId));
$assertion->setAttributes($returnAttributes);
$assertion->setAttributeNameFormat($attributeNameFormat);
sspmod_saml_Message::addSign($aaMetadata, $spMetadata, $assertion);

/* The Response */
$response = new SAML2_Response();
$response->setRelayState($query->getRelayState());
$response->setIssuer($aaEntityId);
$response->setInResponseTo($query->getId());
$response->setAssertions(array($assertion));
sspmod_saml_Message::addSign($aaMetadata, $spMetadata, $response);


/* Send */
SimpleSAML_Logger::debug('[aa] Sending: '.var_export($response,true));
SimpleSAML_Logger::info('[aa] Sending assertion.');
$binding->send($response);