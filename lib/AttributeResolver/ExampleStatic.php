<?php
class sspmod_aa_AttributeResolver_ExampleStatic extends sspmod_aa_AttributeResolver
{

	public function __construct($config)
	{
        parent::__construct($config);
	}

	public function getAttributes($spid, $subject, $attributes = array())
	{
		$config = $this->config;
		$static_attributes = $config->getArray('attributes');
		if (empty($attributes)){
			return $static_attributes;
		}

		$retarray = array();		
		foreach ($attributes as $attribute) {
			if (array_key_exists($attribute, $static_attributes))
				$retarray[$attribute] = $static_attributes[$attribute];
		}
		return $retarray;
	}
}
