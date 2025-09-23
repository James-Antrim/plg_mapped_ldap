<?php
/**
 * @package     Mapped LDAP
 * @extension   plg_mapped_ldap
 * @author      James Antrim, <james.antrim@nm.thm.de>
 * @copyright   2025 TH Mittelhessen
 * @license     GNU GPL v.3
 * @link        www.thm.de
 */

require_once 'autoloader.php';

use Joomla\CMS\{Extension\PluginInterface, Factory, Plugin\PluginHelper};
use Joomla\DI\{Container, ServiceProviderInterface};
use Joomla\Event\DispatcherInterface;
use THM\MappedLDAP\MappedLDAP;

return new class() implements ServiceProviderInterface {
    public function register(Container $container): void
    {
        $container->set(
            PluginInterface::class,
            function (Container $container) {
                $plugin = new MappedLDAP(
                    $container->get(DispatcherInterface::class),
                    (array) PluginHelper::getPlugin('authentication', 'mapped_ldap')
                );
                $plugin->setApplication(Factory::getApplication());

                return $plugin;
            }
        );
    }
};