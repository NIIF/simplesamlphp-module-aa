<?php
class sspmod_aa_AttributeResolver_Hexaa extends sspmod_aa_AttributeResolver
{

	public function __construct($config)
	{
				
                parent::__construct($config);
	}


	public function getAttributes($eppn, $spid, $attributes = array())
	{
		$config = $this->config;
		
		$epe = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7';
		$retarray = array();
	        date_default_timezone_set('UTC');	
		$time = new \DateTime();
		$stamp = $time->format('Y-m-d H:i');
		$apiKey = hash('sha256',"simplesamlphp"."ssp".$stamp);	
		SimpleSAML_Logger::debug('[aa] Hexaa api query: '.$config->getValue('hexaa_api_url')."/attributes.json?fedid=".urlencode($eppn)."&soid=".urlencode($spid)."apikey=HIDDEN with timestamp: ".$stamp);
		$query = $config->getValue('hexaa_api_url')."/attributes.json?fedid=".urlencode($eppn)."&soid=".urlencode($spid)."&apikey=".$apiKey;
		$result = file_get_contents($query);
		$data = json_decode($result, true);
		return $data;
	}
}
 

