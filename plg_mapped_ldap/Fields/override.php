<?php
/**
 * @package     Mapped LDAP
 * @extension   plg_mapped_ldap
 * @author      James Antrim, <james.antrim@nm.thm.de>
 * @copyright   2021 TH Mittelhessen
 * @license     GNU GPL v.3
 * @link        www.thm.de
 */

use Joomla\CMS\Language\Text;

JFormHelper::loadFieldClass('radio');

/**
 * Class creates text input.
 */
class JFormFieldOverride extends JFormFieldRadio
{
	/**
	 * Method to get the field input markup.
	 *
	 * @return  string  The field input markup.
	 */
	protected function getInput(): string
	{
		$input = parent::getInput();
		$input .= '<br><br>' . Text::_('MAPPED_LDAP_OVERRIDE_DESC');

		return $input;
	}
}
