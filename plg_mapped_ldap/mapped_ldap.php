<?php
/** @noinspection PhpClassNamingConventionInspection */
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
 */
class PlgAuthenticationMapped_LDAP extends JPlugin
{
	private const DIRECT = 1, SEARCH = 0;

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

		// Authentication was not successful.
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

		$this->loadLanguage();
		$email    = reset($result[$email]);
		$name     = reset($result[$name]);
		$override = (bool) $params->get('override');
		$rules    = $params->get('rules');
		$user     = User::getInstance($userName);

		if (!$user->id)
		{
			// Override: no rules, no authentication for new users.
			if ($override and !$rules)
			{
				$response->status        = Authentication::STATUS_FAILURE;
				$response->error_message = $message ?: Text::_('MAPPED_LDAP_NO_RULES');

				return;
			}

			$user->email    = $email;
			$user->name     = $name;
			$user->username = $userName;
		}
		// The user exists and there are no rules to assign them more groups.
		elseif (!$rules)
		{
			$response->email         = $email;
			$response->error_message = '';
			$response->fullname      = $name;
			$response->status        = Authentication::STATUS_SUCCESS;
			$response->username      = $userName;

			return;
		}

		$domain             = (string) $params->get('domain');
		$emails             = (string) $params->get('emails');
		$emails             = empty($result[$emails]) ? [$email] : $result[$emails];
		$assignedLDAPGroups = (string) $params->get('ldap_groups');
		$assignedLDAPGroups = empty($result[$assignedLDAPGroups]) ? [] : $result[$assignedLDAPGroups];

		$existingGroupIDs = $user->groups;
		$groupIDs         = [];

		// Futureproof group id assignment by ensuring that the id is always the same as the value.
		foreach ($existingGroupIDs as $groupID)
		{
			$groupIDs[$groupID] = $groupID;
		}

		foreach ($rules as $rule)
		{
			// The rule does not contain a group assignment => invalid.
			if (!$groupID = (int) $rule->groupID)
			{
				continue;
			}

			// Avoid running trim on individual array items
			$ruleGroups = str_replace(' ', '', $rule->ldap_group);
			$ruleGroups = explode(',', $ruleGroups);
			$subDomains = str_replace(' ', '', $rule->subdomain);
			$subDomains = explode(',', $subDomains);

			// The rule restricts groups and the person is either not assigned a group or not assigned a relevant group.
			if ($ruleGroups and (!$assignedLDAPGroups or !array_intersect($ruleGroups, $assignedLDAPGroups)))
			{
				continue;
			}

			// Check for subdomain relevance
			if ($subDomains)
			{
				$relevant = false;

				foreach ($subDomains as $subDomain)
				{
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
							break 2;
						}
					}
				}

				if (!$relevant)
				{
					continue;
				}
			}

			$groupIDs[$groupID] = $groupID;
		}

		if (!$groupIDs)
		{
			// Override Joomla's handling by not authenticating.
			if ($override and !$user->id)
			{
				$response->status        = Authentication::STATUS_FAILURE;
				$response->error_message = Text::_('MAPPED_LDAP_NO_APPLICABLE_RULES');

				return;
			}

			// Let Joomla do its thing.
			$response->email         = $email;
			$response->error_message = '';
			$response->fullname      = $name;
			$response->status        = Authentication::STATUS_SUCCESS;
			$response->username      = $userName;

			return;
		}

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
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = $message ?: Text::_('JERROR_AN_ERROR_HAS_OCCURRED');

			return;
		}

		$dbo = Factory::getDbo();

		foreach ($groupIDs as $groupID)
		{
			// Skip existing user -> user group assignments.
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

		$response->email         = $email;
		$response->error_message = '';
		$response->fullname      = $name;
		$response->status        = Authentication::STATUS_SUCCESS;
		$response->username      = $userName;
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
