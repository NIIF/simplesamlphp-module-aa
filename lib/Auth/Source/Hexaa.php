<?php
/**
 * Static AA source.
 *
 * This class is the authentication source of th HEXAA backend
 * 
 * Example configuration in the config/authsources.php
 * 
 *       'default-aa' => array(
 *           'aa:Hexaa',
 *            'hexaa_api_url' =>       'https://www.hexaa.example.com/app.php/api',
 *            'hexaa_master_secret' => 'you_can_get_it_from_the_hexaa_administrator'
 *       ),		
 *
 * @author 
 * @package 
 */
class sspmod_aa_Auth_Source_Hexaa extends SimpleSAML_Auth_Source {

    private $config;
    private $as_config;

	public function __construct($info, $config)
	{
	    parent::__construct($info, $config);
	    $params = array(
	    	'hexaa_master_secret',
	    	'hexaa_api_url'
	    	);
	    foreach ($params as $param) {
	    	if (!array_key_exists($param, $config)) {
				throw new Exception('Missing required attribute \'' . $param .
				'\' for authentication source ' . $this->authId);
			}
			$this->as_config[$param] = $config[$param];
	    }                     			
	}

	public function authenticate(&$state) {
		assert('is_array($state)');
		$nameId = $state['aa:nameId'];
		$spid = $state['Destination']['entityid'];
		$this->config = SimpleSAML_Configuration::getInstance();
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
		$apiKey = hash('sha256', $this->as_config['hexaa_master_secret'].$stamp);	
		// Make the call
		// The data to send to the API
		$postData = array(
			"apikey" => $apiKey,
	        "fedid" => $nameId,
			"entityid" => $spid
		);


		// Setup cURL
		$ch = curl_init($this->as_config['hexaa_api_url'].'/attributes.json');
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
		$http_response = curl_getinfo($handle, CURLINFO_HTTP_CODE);

		// Check for error; not even redirects are allowed here
		if ($response === FALSE || !($http_response >= 200 && $http_response < 300)){
		    SimpleSAML_Logger::error('[aa] HEXAA API query failed: HTTP response: $http_response, curl error: "'.curl_error($ch)) .'"';
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
 

