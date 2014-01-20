<?php

$this->data['header'] = $this->t('aa_header');
$this->includeAtTemplateBase('includes/header.php');
?>

<dl>
<dt><?php echo $this->t('select') ?></dt>
<dd><?php echo $this->data['data']['select'] ?></dd>

<dt><?php echo $this->t('fid') ?></dt>
<dd><?php echo $this->data['data']['fid'] ?></dd>

<dt><?php echo $this->t('mapping') ?></dt>

</dl>

<table class="enablebox table attributes">
<?php foreach ($this->data['data']['mapping'] as $spid => $regexps) :?>
<tr>
<td><?php echo $spid ?></td>
<td>
<?php foreach ($regexps as $regexp) :?>
<?php echo $regexp ?>
<br>
<?php endforeach ?>
</td>
</tr>
<?php endforeach ?>
</table>
</div>

<?php
$this->includeAtTemplateBase('includes/footer.php');
?>
