<?php

/**
 * Static AA source.
 *
 * This class is an example authentication source which will always return a user with
 * a static set of attributes.
 * 
 * Example configuration in the config/authsources.php
 * 
 *       'default-aa' => array(
 *           'aa:Static',
 *           'attributes' => array(
 *               'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => array(
 *                   'urn:oid:test-from-aa'          // eduPersonEntitlement
 *               ),
 *               'urn:oid:0.9.2342.19200300.100.1.3' => array(
 *                    'testuser+from-aa@example.com' //mail
 *               ),
 *               'urn:oid:2.16.840.1.113730.3.1.39' => array(
 *                    'hu-from-aa'                   //preferredlanguage
 *               )
 *            )
 *       ),		
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