<?php

/* Load simpleSAMLphp, configuration and metadata */
$config = SimpleSAML_Configuration::getInstance();
$metadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();

/* Check if valid local session exists.. */
if ($config->getBoolean('admin.protectmetadata', false)) {
    SimpleSAML_Utilities::requireAdmin();
}

try {
    $aaentityid = isset($_GET['aaentityid']) ? $_GET['aaentityid'] : $metadata->getMetaDataCurrentEntityID('attributeauthority-hosted');
    $aameta = $metadata->getMetaDataConfig($aaentityid, 'attributeauthority-hosted');

    $availableCerts = array();

    $keys = array();
    $certInfo = SimpleSAML_Utilities::loadPublicKey($aameta, false, 'new_');
    if ($certInfo !== null) {
        $availableCerts['new_aa.crt'] = $certInfo;
        $keys[] = array(
            'type' => 'X509Certificate',
            'signing' => true,
            'encryption' => true,
            'X509Certificate' => $certInfo['certData'],
        );
        $hasNewCert = true;
    } else {
        $hasNewCert = false;
    }

    $certInfo = SimpleSAML_Utilities::loadPublicKey($aameta, true);
    $availableCerts['aa.crt'] = $certInfo;
    $keys[] = array(
        'type' => 'X509Certificate',
        'signing' => true,
        'encryption' => ($hasNewCert ? false : true),
        'X509Certificate' => $certInfo['certData'],
    );

    if ($aameta->hasValue('https.certificate')) {
        $httpsCert = SimpleSAML_Utilities::loadPublicKey($aameta, true, 'https.');
        assert('isset($httpsCert["certData"])');
        $availableCerts['https.crt'] = $httpsCert;
        $keys[] = array(
            'type' => 'X509Certificate',
            'signing' => true,
            'encryption' => false,
            'X509Certificate' => $httpsCert['certData'],
        );
    }

    $metaArray = array(
        'metadata-set' => 'attributeauthority-hosted',
        'entityid' => $aaentityid,
        'protocols' => array(SAML2_Const::NS_SAMLP),
        'AttributeService' => array(0 => array(
                            'Binding' => SAML2_Const::BINDING_SOAP,
                            'Location' => SimpleSAML_Utilities::getBaseURL().'module.php/aa/attributeserver.php',
                                         ),
                                       ),
    );

    if (count($keys) === 1) {
        $metaArray['certData'] = $keys[0]['X509Certificate'];
    } else {
        $metaArray['keys'] = $keys;
    }

    $metaArray['NameIDFormat'] = array(
                SAML2_Const::NAMEID_PERSISTENT,
                SAML2_Const::NAMEID_TRANSIENT,
                );

    if ($aameta->hasValue('OrganizationName')) {
        $metaArray['OrganizationName'] = $aameta->getLocalizedString('OrganizationName');
        $metaArray['OrganizationDisplayName'] = $aameta->getLocalizedString(
            'OrganizationDisplayName',
            $metaArray['OrganizationName']
        );

        if (!$aameta->hasValue('OrganizationURL')) {
            throw new SimpleSAML_Error_Exception('If OrganizationName is set, OrganizationURL must also be set.');
        }
        $metaArray['OrganizationURL'] = $aameta->getLocalizedString('OrganizationURL');
    }

    if ($aameta->hasValue('scope')) {
        $metaArray['scope'] = $aameta->getArray('scope');
    }

    $metaflat = '$metadata['.var_export($aaentityid, true).'] = '.var_export($metaArray, true).';';

    $metaBuilder = new SimpleSAML_Metadata_SAMLBuilder($aaentityid);
    $metaBuilder->addAttributeAuthority($metaArray);
    $metaBuilder->addOrganizationInfo($metaArray);
    $technicalContactEmail = $config->getString('technicalcontact_email', null);
    $technicalContactName  = $config->getString('technicalcontact_name', null);
    if ($technicalContactEmail and $technicalContactEmail !== 'na@example.org') {
        $metaBuilder->addContact(
            'technical',
            array(
                'contactType' => 'technical',
                'emailAddress' => $technicalContactEmail,
                'name' => $technicalContactName
            )
        );
    }
    $metaxml = $metaBuilder->getEntityDescriptorText();

    /* Sign the metadata if enabled. */
    $metaxml = SimpleSAML_Metadata_Signer::sign($metaxml, $aameta->toArray(), 'SAML 2 IdP');

    if (array_key_exists('output', $_GET) && $_GET['output'] == 'xhtml') {
        $defaultaa = null;

        $t = new SimpleSAML_XHTML_Template($config, 'metadata.php', 'admin');

        $t->data['header'] = 'saml20-aa';
        $t->data['metaurl'] = SimpleSAML_Utilities::selfURLNoQuery();
        $t->data['metadata'] = htmlspecialchars($metaxml);
        $t->data['metadataflat'] = htmlspecialchars($metaflat);
        $t->data['defaultaa'] = $defaultaa;
        $t->show();
    } else {
        header('Content-Type: application/xml');

        echo $metaxml;
        exit(0);
    }
} catch (Exception $exception) {
    throw new SimpleSAML_Error_Error('METADATA', $exception);
}
