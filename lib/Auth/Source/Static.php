<?php

/**
 * Static AA source.
 *
 * This class is an example authentication source which will always return a user with
 * a static set of attributes.
 *
 * @author 
 * @package 
 */
class sspmod_aa_Auth_Source_Static extends SimpleSAML_Auth_Source {


	/**
	 * The attributes we return.
	 */
	private $attributes;


	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */
	public function __construct($info, $config) {
		assert('is_array($info)');
		assert('is_array($config)');
		assert('is_array($config["attributes"])');

		/* Call the parent constructor first, as required by the interface. */
		parent::__construct($info, $config);


		SimpleSAML_Logger::debug('[aa] auth source static: config: '. var_export($config['attributes'],1));
		$this->attributes = $config['attributes'];
		
	}


	/**
	 * Log in using static attributes.
	 *
	 * @param array &$state  Information about the current authentication.
	 */
	public function authenticate(&$state) {
		assert('is_array($state)');

		$state['Attributes'] = $this->attributes;
	}

}

?>