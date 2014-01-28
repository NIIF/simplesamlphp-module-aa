<?php

$this->data['header'] = $this->t('aa_header');
$this->includeAtTemplateBase('includes/header.php');
?>

<dl>
<dt><?php echo $this->t('resolver') ?></dt>
<dd><?php echo $this->data['data']['resolver'] ?></dd>

<dt><?php echo $this->t('examplestatic_attributes') ?></dt>

</dl>

<table class="enablebox table attributes">
<?php foreach ($this->data['data']['attributes'] as $key => $value) :?>
<tr>
<td><?php echo $key ?></td>
<td>
<?php echo $value ?>
</td>
</tr>
<?php endforeach ?>
</table>
</div>

<?php
$this->includeAtTemplateBase('includes/footer.php');
?>
