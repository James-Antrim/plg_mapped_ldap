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

use Joomla\CMS\{Access\Access, Helper\UserGroupsHelper};
use Joomla\CMS\Form\Field\UsergrouplistField;

/**
 * @inheritDoc
 * Overrides the presentation of Usergroup List Field to disable fields with "core.admin" rights.
 */
class GroupID extends UsergrouplistField
{
    /** @inheritDoc */
    protected function getOptions(): array
    {
        // Hash for caching
        $hash = md5($this->element);

        if (!isset(static::$options[$hash])) {
            $groups  = UserGroupsHelper::getInstance()->getAll();
            $options = [];

            foreach ($groups as $group) {
                $option = [
                    'level' => $group->level,
                    'text'  => str_repeat('- ', $group->level) . $group->title,
                    'value' => $group->id
                ];

                if (Access::checkGroup($group->id, 'core.admin')) {
                    $option['disable'] = 1;
                }

                $options[] = (object) $option;
            }

            static::$options[$hash] = $options;
        }

        return static::$options[$hash];
    }
}