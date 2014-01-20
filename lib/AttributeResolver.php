<?php

/**
 * 
 */
abstract class  sspmod_aa_AttributeResolver
{
        public $config;

	protected function __construct($config)
	{
		// TODO why? assert('is_array($config)');
                $this->config = $config;
	}
	
	abstract public function getAttributes($eppn,$spid);	
}
