<?php

/**
 * 
 */
abstract class  sspmod_aa_AttributeResolver
{
        public $config;

	protected function __construct($config)
	{
        $this->config = $config;
	}
	
	abstract public function getAttributes($subject, $spid, $attributes);	
}