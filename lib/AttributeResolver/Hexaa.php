<?php
class sspmod_aa_AttributeResolver_Hexaa extends sspmod_aa_AttributeResolver
{

	public function __construct($config)
	{
		private $aa_config;
		
                parent::__construct();
		// it is necessery for not come php notice of the opened session.
		//session_destroy();
		$this->aa_config = $config;
	}
	
	private function generateApiKey(){
		date_default_timezone_set('UTC');
		$time = new \DateTime();
		$tstamp = $time->format('Y-m-d H:i');
		$apiKey = hash('sha256',"simplesamlphp"."ssp".$stamp);
		return $apiKey;
	}

	public function getAttributes($eppn, $spid, $attributes = array())
	{
		
		$epe = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7';
		$retarray = array();
		
		$apiKey = generateApiKey();		
		$query($aa_config->getValue('hexaa_api_url')."/attributes/".$eppn."/".$spid."?apikey=".$apikey);
		
		$ch = curl_init($query);
		$options = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HTTPHEADER => array('Content-type: application/json')		
		);
		curl_setopt_array($ch, $options);
		$result = curl_exec($ch);
		
		$data = json_decode($result);
*/		return $data;
	}
}