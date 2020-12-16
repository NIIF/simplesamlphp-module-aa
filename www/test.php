<?php
/**
 *
 * @author gyufi@szabocsalad.com
 * @author gyufi@sztaki.hu
 * @package
 */

require_once('_include.php');

SimpleSAML\Utils\Auth::requireAdmin();
SimpleSAML\Logger::info('SAML2.0 - AA Server: access testpage');

$t = new SimpleSAML\XHTML\Template($config, 'aa:status.php');
$t->getTwig()->enableDebug();
$t->getTwig()->addExtension(new Twig\Extension\DebugExtension());

$metadata = SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();

$aaEntityId = $metadata->getMetaDataCurrentEntityID('attributeauthority-hosted');
$aaMetadata = $metadata->getMetadataConfig($aaEntityId, 'attributeauthority-hosted');

$config = \SimpleSAML\Configuration::getInstance();
$configauthproc = $config->getArray('authproc.aa', null);
$t->data['configauthproc'] = $configauthproc;

$spMetadatas = $metadata->getList('saml20-sp-remote');
$t->data['sps'] = $spMetadatas;

$attributes = [];

try {
    if ($_POST['keyattributename'] && $_POST['keyattributevalue']) {
        $attributes[$_POST['keyattributename']] = [0 => $_POST['keyattributevalue']];
    }
    $t->data['attributes'] = $attributes;

    if ($_POST['sp']) {
        $spEntityId = $_POST['sp'];
        $spMetadataArray = $metadata->getMetaData($spEntityId, 'saml20-sp-remote');
        $pc = new \SimpleSAML\Auth\ProcessingChain($aaMetadata->toArray(), $spMetadataArray, 'aa');
        $authProcState = [
            'Attributes'  => $attributes,
            'Destination' => $spMetadataArray,
            'Source'      => $aaMetadata->toArray(),
        ];
        $pc->processStatePassive($authProcState);
        $processedattributes = $authProcState['Attributes'];
        $t->data['processedattributes'] = $processedattributes;
    }

} catch (Exception $exception) {
    $t->data['exception'] = $exception->getMessage();
    $t->send();
}

if (!empty($debug)) {
    $t->data['debug'] = var_export($debug, true);
}

$t->send();
