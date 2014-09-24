<?php
/**
 * The attributeserver is part of the SAML 2.0 AA code, and it receives incoming Attribte Queries
 * from a SAML 2.0 SP, parses, validate and process it, and then sends back the Response.
 *
 * @author 
 * @package 
 */

require_once('_include.php');

SimpleSAML_Logger::info('SAML2.0 - AA Server: Request at SAML 2.0 Attribute Authority endpoint');

$metadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();

$aa = new sspmod_aa_AA_SAML2($metadata);

$aa->handleAttributeQuery();

assert('FALSE');
