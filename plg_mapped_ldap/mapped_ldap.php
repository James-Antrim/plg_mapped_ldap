<?php /** @noinspection PhpClassNamingConventionInspection */
/** @noinspection PhpDeprecationInspection */
/**
 * @package     Mapped LDAP
 * @extension   plg_mapped_ldap
 * @author      James Antrim, <james.antrim@nm.thm.de>
 * @copyright   2021 TH Mittelhessen
 * @license     GNU GPL v.3
 * @link        www.thm.de
 */

defined('_JEXEC') or die;

use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Authentication\AuthenticationResponse;
use Joomla\CMS\Component\ComponentHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\User\User;
use Joomla\Ldap\LdapClient as Client;

/**
 * Mapped LDAP Authentication Plugin
 *
 * @todo add custom field with radio button and explanatory text to block authentication of new users not matching a rule
 * @todo make the subdomain resolution based on a comma seperated list
 * @todo add an update hook
 */
class PlgAuthenticationMapped_LDAP extends JPlugin
{
	private const ADMINISTRATOR = 7, CORRECT = 1, DIRECT = 1, MANAGER = 6, SEARCH = 0, SUPERADMINISTRATOR = 8, SUPPLEMENT = 0;

	/**
	 * Authenticates a user and maps it into specifically configured groups or the configured default group.
	 *
	 * @param   array                   $credentials  Array holding the user credentials
	 * @param   array                   $options      Array of extra options
	 * @param   AuthenticationResponse  $response     AuthenticationResponse object
	 *
	 * @return  void success is stored in the response->status
	 * @noinspection PhpUnusedParameterInspection
	 * @throws Exception
	 */
	public function onUserAuthenticate(array $credentials, array $options, AuthenticationResponse $response)
	{
		$response->type = 'LDAP';

		// Strip null bytes from the password
		$credentials['password'] = str_replace(chr(0), '', $credentials['password']);

		if (empty($credentials['password']))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');

			return;
		}

		$method = (int) $this->params->get('method');
		$params = $this->params;

		// This is no longer optional.
		$params->set('use_ldapV3', 1);

		// Properties not explicitly mentioned are bound implicitly in the client constructor
		$client = new Client($params);

		if (!$client->connect())
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('JGLOBAL_AUTH_NOT_CONNECT');

			return;
		}

		$message  = '';
		$userName = $credentials['username'];
		$result   = [];
		$search   = str_replace(
			'[search]',
			str_replace(';', '\3b', $client->escape($userName, null, LDAP_ESCAPE_FILTER)),
			$params->get('search')
		);
		$success  = false;

		switch ($method)
		{
			case self::SEARCH:

				// Without altering the client, this parameter cannot be change to be more appropriate.
				$adminName = $params->get('username', '');
				$binds     = $adminName ? $client->bind() : $client->anonymous_bind();

				if ($binds)
				{
					$result = $this->search($client, $search);

					if (empty($result) or empty($result['dn']) or !$success = $client->bind($result['dn'], $credentials['password'], 1))
					{
						$message = Text::_('JGLOBAL_AUTH_NO_USER');
					}
				}
				else
				{
					$message = Text::_('JGLOBAL_AUTH_NOT_CONNECT');
				}

				break;

			case self::DIRECT:

				// We just accept the result here
				if ($success = $client->bind($client->escape($userName, null, LDAP_ESCAPE_DN), $credentials['password']))
				{
					$result = $this->search($client, $search);
				}
				else
				{
					$message = Text::_('JGLOBAL_AUTH_INVALID_PASS');
				}

				break;
		}

		$client->close();

		if (!$success or empty($result))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = $message ?: Text::_('JGLOBAL_AUTH_INVALID_PASS');

			return;
		}

		$email = (string) $params->get('email');
		$name  = (string) $params->get('name');

		if (empty($result[$email]) or empty($result[$name]))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('JGLOBAL_AUTH_USER_NOT_FOUND');

			return;
		}

		$email = reset($result[$email]);
		$name  = reset($result[$name]);

		// Complete the actual authentication
		$response->email         = $email;
		$response->error_message = '';
		$response->fullname      = $name;
		$response->status        = Authentication::STATUS_SUCCESS;
		$response->username      = $userName;

		// No rules to apply => done
		if (!$rules = $params->get('rules'))
		{
			return;
		}

		$domain     = (string) $params->get('domain');
		$emails     = (string) $params->get('emails');
		$emails     = empty($result[$emails]) ? [$email] : $result[$emails];
		$handling   = (int) $params->get('handling', self::SUPPLEMENT);
		$ldapGroups = (string) $params->get('ldap_groups');
		$ldapGroups = empty($result[$ldapGroups]) ? [] : $result[$ldapGroups];
		$user       = User::getInstance($userName);

		if (!$user->id)
		{
			$user->email    = $email;
			$user->name     = $name;
			$user->username = $userName;
		}

		$existingGroupIDs  = $user->groups;
		$groupIDs          = [];
		$protectedGroupIDs = [self::ADMINISTRATOR, self::MANAGER, self::SUPERADMINISTRATOR];

		/**
		 * Futureproof group id assignment.
		 */
		foreach ($existingGroupIDs as $groupID)
		{
			if ($handling === self::CORRECT and !in_array($groupID, $protectedGroupIDs))
			{
				continue;
			}

			$groupIDs[$groupID] = $groupID;
		}

		foreach ($rules as $rule)
		{
			// Since the validation of plugin parameters is spotty, better to validate here.
			if (!$groupID = (int) $rule->groupID)
			{
				continue;
			}

			// Avoid running trim on individual array items
			$groups    = str_replace(' ', '', $rule->ldap_group);
			$groups    = explode(',', $groups);
			$subDomain = $rule->subdomain;

			// Check for group relevance
			if ($groups and !array_intersect($groups, $ldapGroups))
			{
				continue;
			}

			// Check for subdomain relevance
			if ($subDomain)
			{
				$relevant = false;

				// Email was already assigned => variable name safe.
				foreach ($emails as $email)
				{
					$pieces = explode('@', $email);

					// Invalid or irrelevant
					if (!$emailDomain = array_pop($pieces) or strpos($emailDomain, ".$domain") === false)
					{
						continue;
					}

					if (str_replace(".$domain", '', $emailDomain) === $subDomain)
					{
						$relevant = true;
						break;
					}
				}

				if (!$relevant)
				{
					continue;
				}
			}

			$groupIDs[$groupID] = $groupID;
		}

		if ($groupIDs)
		{
			$new = false;

			// Create a new user with the default group id
			if (empty($user->id))
			{
				$defaultID = ComponentHelper::getParams('com_users')->get('new_usertype');
				$new       = true;

				$user->groups[$defaultID] = $defaultID;
				$user->save();
			}

			// Joomla internal problems
			if (empty($user->id))
			{
				return;
			}

			$dbo = Factory::getDbo();

			foreach ($groupIDs as $groupID)
			{
				if (!$new)
				{
					$query = $dbo->getQuery(true);
					$query->select('*')->from('#__user_usergroup_map')->where("user_id = $user->id")->where("group_id = $groupID");
					$dbo->setQuery($query);
					$row = $dbo->loadAssoc();

					if ($row)
					{
						continue;
					}
				}

				$query = $dbo->getQuery(true);
				$query->insert('#__user_usergroup_map')->columns('group_id, user_id')->values("$groupID, $user->id");
				$dbo->setQuery($query);
				$dbo->execute();
			}

			$groupIDs = implode(',', $groupIDs);
			$query    = $dbo->getQuery(true);
			$query->delete('#__user_usergroup_map')->where("user_id = $user->id")->where("group_id NOT IN ($groupIDs)");
			$dbo->setQuery($query);
			$dbo->execute();
		}
	}

	/**
	 * Builds a search string based on semicolon separated items. Calls the client search function. Returns the first
	 * result.
	 *
	 * @param   Client  $client  the LDAP client
	 * @param   string  $search  search string of search values
	 *
	 * @return  array  Search result (singular)
	 */
	private function search(Client $client, string $search): array
	{
		$results = explode(';', $search);

		foreach ($results as $key => $result)
		{
			$results[$key] = '(' . str_replace('\3b', ';', $result) . ')';
		}

		$results = $client->search($results);

		return reset($results) ?: [];
	}
}
