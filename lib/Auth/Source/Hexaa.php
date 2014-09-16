<?php
class sspmod_aa_Auth_Source_Hexaa extends SimpleSAML_Auth_Source {

	public function __construct($config)
	{
                parent::__construct($config);
	}

	public function authenticate(&$state) {
		assert('is_array($state)');
		$nameId = $state['aa:nameId'];
		$spId = $state['Destination']['entityId'];
		$state['Attributes'] = $this->getAttributes($nameId,$spid);
	}

	public function getAttributes($nameId, $spid, $attributes = array())
	{
		// Set up config
		$config = $this->config;
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
		        "fedid" => $nameId,
			"entityid" => $spid
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
		SimpleSAML_Logger::debug('[aa] HEXAA API query postData: '.var_export($postData, TRUE));
		SimpleSAML_Logger::debug('[aa] HEXAA API query result: '.var_export($data, TRUE));
		}	
		return $data;
	}
}
 

