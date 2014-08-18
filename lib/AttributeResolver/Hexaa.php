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
		$time = new \DateTime();
	        date_timezone_set($time, new \DateTimeZone('UTC'));
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
		SimpleSAML_Logger::info('[aa] got reply from HEXAA API');
		SimpleSAML_Logger::debug('[aa] HEXAA API query result: '.var_export($data, TRUE));
		}
		return $data;
	}
}
 

