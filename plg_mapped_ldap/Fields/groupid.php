<?php

use Joomla\CMS\Access\Access;
use Joomla\CMS\Form\Field\UsergrouplistField;
use Joomla\CMS\Helper\UserGroupsHelper;

/**
 *  Overrides the presentation of Usergroup List Field to disable fields with "core.admin" rights.
 */
class JFormFieldGroupid extends UsergrouplistField
{
    /**
     * Method to get the options to populate list
     *
     * @return  array  The field option objects.
     */
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