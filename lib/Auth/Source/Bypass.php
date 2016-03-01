<?php

/**
 * Bypass AA source.
 *
 * This class is an authentication source which will always return a user with
 * the subject nameId in the attributes array.
 *
 * Example configuration in the config/authsources.php
 *
 *       'default-aa' => array(
 *           'aa:Bypass',
 *           'uid' => 'subject_nameid'
 *       ),
 *
 * @author Gyula Szabó <gyufi@niif.hu>
 */
class sspmod_aa_Auth_Source_Bypass extends SimpleSAML_Auth_Source
{
    /**
     * Attribute name for the subject nameId.
     *
     * @var string
     **/
    private $uid;

    /**
     * Constructor for this authentication source.
     *
     * @param array $info   Information about this authentication source.
     * @param array $config Configuration.
     */
    public function __construct($info, $config)
    {
        assert('is_array($info)');
        assert('is_array($config)');

        /* Call the parent constructor first, as required by the interface. */
        parent::__construct($info, $config);

        if (!array_key_exists('uid', $config) || !is_string($config['uid'])) {
            throw new SimpleSAML_Error_Exception("AA configuration error, 'uid' not found or not a string.");
        }

        SimpleSAML_Logger::debug('[aa] auth source Bypass: config uid: '.$config['uid']);
        $this->uid = $config['uid'];
    }

    /**
     * Log in and set the nameId attribute.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(&$state)
    {
        assert('is_array($state)');

        $state['Attributes'][$this->uid] = array($state['aa:nameId']);
    }
}
