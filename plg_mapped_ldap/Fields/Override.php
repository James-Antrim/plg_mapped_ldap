<?php
/**
 * @package     Mapped LDAP
 * @extension   plg_mapped_ldap
 * @author      James Antrim, <james.antrim@nm.thm.de>
 * @copyright   2021 TH Mittelhessen
 * @license     GNU GPL v.3
 * @link        www.thm.de
 */

namespace THM\MappedLDAP\Fields;

use Joomla\CMS\Form\Field\RadioField;
use Joomla\CMS\Language\Text;

/**
 * Class creates text input.
 */
class Override extends RadioField
{
    /** @inheritDoc */
    protected function getInput(): string
    {
        $input = parent::getInput();
        $input .= '<br><br>' . Text::_('MAPPED_LDAP_OVERRIDE_DESC');

        return $input;
    }
}
