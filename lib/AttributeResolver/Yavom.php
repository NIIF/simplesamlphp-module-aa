<?php
class sspmod_aa_AttributeResolver_Yavom extends sspmod_aa_AttributeResolver
{

	public function __construct()
	{
                parent::__construct();
		// it is necessery for not come php notice of the opened session.
		session_destroy();
		/*  Include YAVOM symfony class. Not part of simpleSAMLphp  */		
		require_once(dirname(__FILE__).'../../../../../../../../config/ProjectConfiguration.class.php');
		$configuration = ProjectConfiguration::getApplicationConfiguration('frontend', 'dev', true);
		sfContext::createInstance($configuration);
	}

	public function getAttributes($spid, $eppn, $attributes = array())
	{
		/*  AttributeResolver class from YAVOM, not SSP */
		/*  Getting the related attributes for user and the related SP from YAVOM database */
		$epe = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7';
		$retarray = array();

		$ar = new AttributeResolver();
		$uris = $ar->getUrisForEppnToSpid($eppn,$spid);


		foreach ($uris as $uri){
			$retarray[$epe][] = $uri;				
		}
		return $retarray;
	}
}
