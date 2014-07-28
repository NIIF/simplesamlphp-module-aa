<?php
class sspmod_aa_AttributeResolver_Hexaa extends sspmod_aa_AttributeResolver
{

	public function __construct($config)
	{
				
                parent::__construct($config);
	}


	public function getAttributes($eppn, $spid, $attributes = array())
	{
		// Set up config
		$config = $this->config;
		$epe = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7';
		$retarray = array();
		
		// Generate API key
	        date_default_timezone_set('UTC');	
		$time = new \DateTime();
		$stamp = $time->format('Y-m-d H:i');
		$apiKey = hash('sha256', $config->getValue('hexaa_master_secret').$stamp);	
	
		// Make the call
		// The data to send to the API
		$postData = array(
			"apikey" => $apiKey,
		        "fedid" => $eppn,
			"soid" => $spid
		);


		// Setup cURL
		$ch = curl_init($config->getValue('hexaa_api_url').'/attributes.json');
		curl_setopt_array($ch, array(
		        CURLOPT_POST => TRUE,
		        CURLOPT_RETURNTRANSFER => TRUE,
		        CURLOPT_HTTPHEADER => array(
		            'Content-Type: application/json'
		        ),
		        CURLOPT_POSTFIELDS => json_encode($postData),
    		));

		// Send the request
		$response = curl_exec($ch);

		// Check for error & use the data
		if ($response === FALSE){
		SimpleSAML_Logger::error('[aa] HEXAA API query failed: '.curl_error($ch));
		$data = array();
		} else {
		        $data = json_decode($response, true);
		SimpleSAML_Logger::info('[aa] HEXAA API query successful');
		SimpleSAML_Logger::debug('[aa] HEXAA API query result: '.var_export($datai, TRUE));
		}
		return $data;
	}
}
 

