<?php

/**
 * Hook to add the modinfo module to the frontpage.
 *
 * @param array &$links The links on the frontpage, split into sections.
 */
function aa_hook_frontpage(&$links)
{
    assert('is_array($links)');
    assert('array_key_exists("links", $links)');

    $links['config'][] = array(
        'href' => SimpleSAML_Module::getModuleURL('aa/test.php'),
        'text' => 'Attribute Authority test page',
    );

    $links['federation'][] = array(
        'href' => SimpleSAML_Module::getModuleURL('aa/metadata.php?output=xhtml'),
        'text' => '{aa:aa:text}',
    );
}
