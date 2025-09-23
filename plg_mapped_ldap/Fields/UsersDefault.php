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

use Joomla\CMS\Component\ComponentHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Form\FormField;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Table\Usergroup;

/**
 * Class creates text input.
 */
class UsersDefault extends FormField
{
    /**
     * Method to get the field input markup.
     *
     * @return  string  The field input markup.
     */
    protected function getInput(): string
    {
        $params = ComponentHelper::getParams('com_users');

        if ($params->get('allowUserRegistration')) {
            $group = new Usergroup(Factory::getDbo());

            if ($groupID = $params->get('new_usertype') and $group->load($groupID)) {
                $return = Text::sprintf('MAPPED_LDAP_REGISTRATION_ALLOWED', $group->get('title'));
            }
            else {
                $return = Text::_('MAPPED_LDAP_REGISTRATION_NO_GROUP_SELECTED');
            }
        }
        else {
            $return = Text::_('MAPPED_LDAP_REGISTRATION_NOT_ALLOWED');
        }

        return $return;
    }
}
