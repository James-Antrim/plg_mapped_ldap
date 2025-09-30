<?php
/**
 * @package     MappedLDAP
 * @extension   plg_mapped_ldap
 * @author      James Antrim, <james.antrim@nm.thm.de>
 * @copyright   2025 TH Mittelhessen
 * @license     GNU GPL v.3
 * @link        www.thm.de
 */

defined('_JEXEC') or die;

spl_autoload_register(function ($originalClassName) {

    $classNameParts = explode('\\', $originalClassName);

    if (array_shift($classNameParts) !== 'THM' or array_shift($classNameParts) !== 'MappedLDAP') {
        return;
    }

    require_once JPATH_ROOT . "/plugins/authentication/mapped_ldap/MappedLDAP.php";
});
